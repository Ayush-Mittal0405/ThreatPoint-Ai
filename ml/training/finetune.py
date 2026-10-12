"""
AegisX QLoRA Fine-Tuning Pipeline.

Fine-tunes base LLMs (Llama-3.2-3B, Mistral-7B, Qwen-2.5) on domain-specific
cybersecurity investigation and triage datasets using Hugging Face PEFT + TRL.

Features:
  - 4-bit NormalFloat (NF4) quantization via BitsAndBytes
  - Low-Rank Adaptation (LoRA) on attention and MLP projection layers
  - Supervised Fine-Tuning (SFTTrainer) with ChatML message templates
  - LoRA checkpoint saving and Ollama custom Modelfile export
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import structlog
    log = structlog.get_logger()
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    _std_log = logging.getLogger("finetune")
    class _LoggerWrapper:
        def info(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.info(f"{msg} {kw_str}".strip())
        def warning(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.warning(f"{msg} {kw_str}".strip())
        def error(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.error(f"{msg} {kw_str}".strip())
    log = _LoggerWrapper()



DEFAULT_BASE_MODEL = "meta-llama/Llama-3.2-3B-Instruct"
DEFAULT_OUTPUT_DIR = "ml/models/aegisx_soc_lora"


def generate_ollama_modelfile(
    base_model: str,
    adapter_path: str,
    output_modelfile: str = "ml/models/Modelfile",
    system_prompt: Optional[str] = None,
) -> str:
    """
    Generate an Ollama Modelfile to import fine-tuned LoRA weights directly into Ollama:
        ollama create aegisx-soc -f ml/models/Modelfile
    """
    system = system_prompt or (
        "You are AegisX Autonomous SOC Agent, an expert AI cybersecurity assistant "
        "specializing in real-time telemetry triage, autonomous investigation tool selection, "
        "MITRE ATT&CK kill-chain mapping, and response recommendation."
    )

    content = f"""# AegisX Autonomous SOC Agent — Custom Ollama Modelfile
FROM {base_model}
ADAPTER {os.path.abspath(adapter_path)}

PARAMETER temperature 0.2
PARAMETER top_p 0.95
PARAMETER repeat_penalty 1.1
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|end_of_text|>"

SYSTEM \"\"\"{system}\"\"\"
"""
    Path(output_modelfile).parent.mkdir(parents=True, exist_ok=True)
    with open(output_modelfile, "w", encoding="utf-8") as f:
        f.write(content)

    log.info("Ollama Modelfile generated", path=output_modelfile)
    return content


def train_qlora(
    dataset_dir: str = "ml/datasets/processed",
    base_model_name: str = DEFAULT_BASE_MODEL,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    epochs: int = 3,
    batch_size: int = 2,
    learning_rate: float = 2e-4,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Execute QLoRA fine-tuning loop.
    Falls back to configuration / dry-run output if PyTorch/CUDA are not available.
    """
    log.info(
        "Preparing QLoRA training configuration",
        base_model=base_model_name,
        output_dir=output_dir,
        epochs=epochs,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
    )

    train_file = Path(dataset_dir) / "train.jsonl"
    val_file = Path(dataset_dir) / "val.jsonl"

    if not train_file.exists():
        log.error("Training dataset not found. Run dataset_builder.py first.", file=str(train_file))
        return {"status": "error", "message": "Dataset not found"}

    if dry_run:
        log.info("Dry-run requested. Simulating training pipeline setup.")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        modelfile_path = Path(output_dir) / "Modelfile"
        generate_ollama_modelfile(base_model_name, output_dir, str(modelfile_path))
        return {
            "status": "dry_run_complete",
            "base_model": base_model_name,
            "output_dir": output_dir,
            "lora_config": {
                "r": lora_r,
                "alpha": lora_alpha,
                "dropout": lora_dropout,
                "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            },
            "training_args": {
                "epochs": epochs,
                "batch_size": batch_size,
                "learning_rate": learning_rate,
                "quantization": "4bit-NF4",
            },
            "modelfile": str(modelfile_path),
        }

    try:
        import torch
        from datasets import load_dataset
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
        from trl import SFTTrainer

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )

        tokenizer = AutoTokenizer.from_pretrained(base_model_name, use_fast=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
        model = prepare_model_for_kbit_training(model)

        lora_config = LoraConfig(
            r=lora_r,
            lora_alpha=lora_alpha,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            lora_dropout=lora_dropout,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)

        dataset = load_dataset(
            "json",
            data_files={"train": str(train_file), "validation": str(val_file)},
        )

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=4,
            learning_rate=learning_rate,
            logging_steps=10,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            fp16=True,
            optim="paged_adamw_8bit",
            lr_scheduler_type="cosine",
        )

        trainer = SFTTrainer(
            model=model,
            train_dataset=dataset["train"],
            eval_dataset=dataset["validation"],
            peft_config=lora_config,
            dataset_text_field="messages",
            max_seq_length=2048,
            tokenizer=tokenizer,
            args=training_args,
        )

        trainer.train()
        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)

        modelfile_path = Path(output_dir) / "Modelfile"
        generate_ollama_modelfile(base_model_name, output_dir, str(modelfile_path))

        log.info("Fine-tuning completed successfully", output_dir=output_dir)
        return {"status": "trained", "output_dir": output_dir, "modelfile": str(modelfile_path)}

    except ImportError as e:
        log.warning(
            "PyTorch/Transformers/PEFT not installed in local environment. Run in GPU environment: pip install torch peft transformers trl bitsandbytes",
            error=str(e),
        )
        # Fall back to generating artifacts & modelfile
        return train_qlora(
            dataset_dir=dataset_dir,
            base_model_name=base_model_name,
            output_dir=output_dir,
            epochs=epochs,
            batch_size=batch_size,
            dry_run=True,
        )


def main():
    parser = argparse.ArgumentParser(description="AegisX QLoRA Fine-Tuning")
    parser.add_argument("--dataset-dir", default="ml/datasets/processed", help="Dataset directory containing train.jsonl")
    parser.add_argument("--base-model", default=DEFAULT_BASE_MODEL, help="Hugging Face base model name")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to save LoRA adapters")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Per-device batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--dry-run", action="store_true", help="Perform setup without GPU training")

    args = parser.parse_args()

    result = train_qlora(
        dataset_dir=args.dataset_dir,
        base_model_name=args.base_model,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        dry_run=args.dry_run,
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
