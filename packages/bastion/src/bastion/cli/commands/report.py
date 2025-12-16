"""Report command - generate rotation status reports."""

from __future__ import annotations


from ..console import console
from ..helpers import get_db_manager
from ...reports import ReportGenerator


def report_status_impl(db_path) -> None:
    """Generate rotation status report."""
    db_mgr = get_db_manager(db_path)
    db = db_mgr.load()
    
    reporter = ReportGenerator(console)
    reporter.generate_report(db)
