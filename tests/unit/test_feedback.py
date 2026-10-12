"""
Unit tests for the Analyst Feedback & Continuous Learning Endpoint.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.feedback import submit_feedback, feedback_stats, FeedbackIn
from app.models.models import Incident, AnalystFeedback


class TestFeedbackEndpoint:
    def test_submit_feedback_updates_incident(self):
        async def _run():
            inc_id = uuid.uuid4()
            mock_incident = Incident(
                id=inc_id,
                incident_id="INC-2041",
                status="investigating",
                severity="medium",
            )

            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_incident
            mock_db.execute.return_value = mock_result

            body = FeedbackIn(
                rating=4,
                is_false_positive=True,
                category="false_positive",
                analyst_note="Security testing scanner caused alert",
                corrected_severity="low",
            )

            out = await submit_feedback(incident_id=inc_id, body=body, db=mock_db)

            assert out.rating == 4
            assert out.is_false_positive is True
            assert mock_incident.status == "false_positive"
            assert mock_incident.severity == "low"
            assert mock_incident.analyst_feedback["rating"] == 4
            assert mock_incident.analyst_feedback["category"] == "false_positive"
            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()
        asyncio.run(_run())

    def test_feedback_stats_calculation(self):
        async def _run():
            f1 = AnalystFeedback(rating=5, is_false_positive=False, category="accurate")
            f2 = AnalystFeedback(rating=4, is_false_positive=False, category="accurate")
            f3 = AnalystFeedback(rating=1, is_false_positive=True, category="false_positive")

            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [f1, f2, f3]
            mock_db.execute.return_value = mock_result

            stats = await feedback_stats(db=mock_db)

            assert stats["total_feedback"] == 3
            assert stats["average_rating"] == round((5 + 4 + 1) / 3, 2)
            assert stats["false_positive_rate"] == round(1 / 3, 2)
            assert stats["categories"]["accurate"] == 2
            assert stats["categories"]["false_positive"] == 1
        asyncio.run(_run())

    def test_feedback_stats_empty_db(self):
        async def _run():
            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_db.execute.return_value = mock_result

            stats = await feedback_stats(db=mock_db)
            assert stats["total_feedback"] == 0
            assert stats["average_rating"] == 5.0
        asyncio.run(_run())
