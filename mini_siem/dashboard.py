"""Streamlit dashboard for the AI-Powered Mini SIEM."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from ai_analyzer import OllamaSecurityAnalyst
from collector import EventLogAccessError, WindowsEventCollector, seed_sample_logs
from database import DatabaseManager, init_db
from detection_engine import DetectionEngine
from models.alert_model import Alert
from models.log_model import LogRecord


SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


class SIEMDashboard:
    """Render and operate the Streamlit SOC dashboard."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def render(self) -> None:
        """Render the complete dashboard."""
        st.set_page_config(
            page_title="AI-Powered Mini SIEM",
            layout="wide",
        )
        st.title("AI-Powered Mini SIEM for Windows Security Monitoring")

        self._render_sidebar_actions()
        logs_df = self._load_logs()
        alerts_df = self._load_alerts()

        self._render_metrics(logs_df, alerts_df)
        self._render_charts(logs_df, alerts_df)
        self._render_recent_alerts(alerts_df)
        self._render_search(logs_df)
        self._render_ai_section(alerts_df)

    def _render_sidebar_actions(self) -> None:
        st.sidebar.header("Operations")
        collect_limit = st.sidebar.number_input(
            "Collection limit",
            min_value=10,
            max_value=5000,
            value=250,
            step=10,
        )
        include_ai = st.sidebar.checkbox("Use Ollama AI analysis", value=False)
        ollama_model = st.sidebar.text_input("Ollama model", value="qwen2.5:latest")

        if st.sidebar.button("Collect Windows Logs", use_container_width=True):
            with st.spinner("Collecting Windows Security logs..."):
                collector = WindowsEventCollector()
                try:
                    inserted = collector.collect_and_store(
                        self.db,
                        limit=collect_limit,
                    )
                except EventLogAccessError as exc:
                    st.sidebar.error(str(exc))
                    st.warning(
                        "Windows blocked Security log collection. Restart this "
                        "Streamlit app from an Administrator terminal, then try "
                        "Collect Windows Logs again."
                    )
                    inserted = None
                except Exception as exc:
                    st.sidebar.error(f"Collection failed: {exc}")
                    inserted = None
            if inserted is not None:
                st.sidebar.success(f"Inserted {inserted} new logs.")

        if st.sidebar.button("Load Sample Logs", use_container_width=True):
            inserted = seed_sample_logs(self.db)
            st.sidebar.success(f"Inserted {inserted} sample logs.")

        if st.sidebar.button("Run Detection Engine", use_container_width=True):
            with st.spinner("Running rules and generating alerts..."):
                analyst = OllamaSecurityAnalyst(
                    model=ollama_model,
                    enabled=include_ai,
                )
                engine = DetectionEngine(self.db, ai_analyzer=analyst)
                created = engine.run(include_ai=True)
            st.sidebar.success(f"Created {created} alerts.")

    def _load_logs(self) -> pd.DataFrame:
        with self.db.session_scope() as session:
            rows = session.query(LogRecord).order_by(LogRecord.timestamp.desc()).all()
            return pd.DataFrame([row.to_dict() for row in rows])

    def _load_alerts(self) -> pd.DataFrame:
        with self.db.session_scope() as session:
            rows = session.query(Alert).order_by(Alert.timestamp.desc()).all()
            return pd.DataFrame([row.to_dict() for row in rows])

    def _render_metrics(self, logs_df: pd.DataFrame, alerts_df: pd.DataFrame) -> None:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Logs", len(logs_df))
        col2.metric("Total Alerts", len(alerts_df))
        high_count = self._severity_count(alerts_df, "High")
        critical_count = self._severity_count(alerts_df, "Critical")
        col3.metric("High Alerts", high_count)
        col4.metric("Critical Alerts", critical_count)

    @staticmethod
    def _severity_count(alerts_df: pd.DataFrame, severity: str) -> int:
        if alerts_df.empty or "severity" not in alerts_df:
            return 0
        return int((alerts_df["severity"] == severity).sum())

    def _render_charts(self, logs_df: pd.DataFrame, alerts_df: pd.DataFrame) -> None:
        st.subheader("Security Overview")
        col1, col2 = st.columns(2)

        with col1:
            if alerts_df.empty:
                st.info("No alerts available yet.")
            else:
                severity_df = (
                    alerts_df["severity"]
                    .value_counts()
                    .reindex(SEVERITY_ORDER, fill_value=0)
                    .reset_index()
                )
                severity_df.columns = ["severity", "count"]
                fig = px.bar(
                    severity_df,
                    x="severity",
                    y="count",
                    color="severity",
                    title="Severity Breakdown",
                    category_orders={"severity": SEVERITY_ORDER},
                )
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            if logs_df.empty:
                st.info("No logs available yet.")
            else:
                event_df = logs_df["event_id"].value_counts().reset_index()
                event_df.columns = ["event_id", "count"]
                fig = px.pie(
                    event_df,
                    names="event_id",
                    values="count",
                    title="Event ID Distribution",
                )
                st.plotly_chart(fig, use_container_width=True)

        if not logs_df.empty:
            timeline_df = logs_df.copy()
            timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"])
            timeline_df = (
                timeline_df.set_index("timestamp")
                .resample("5min")
                .size()
                .reset_index(name="events")
            )
            fig = px.line(
                timeline_df,
                x="timestamp",
                y="events",
                title="Log Timeline",
            )
            st.plotly_chart(fig, use_container_width=True)

    def _render_recent_alerts(self, alerts_df: pd.DataFrame) -> None:
        st.subheader("Recent Alerts")
        if alerts_df.empty:
            st.info("No alerts generated yet.")
            return

        columns = ["timestamp", "severity", "title", "description"]
        st.dataframe(alerts_df[columns].head(50), use_container_width=True)

    def _render_search(self, logs_df: pd.DataFrame) -> None:
        st.subheader("Search Logs")
        if logs_df.empty:
            st.info("Collect Windows Security logs to begin searching.")
            return

        col1, col2, col3 = st.columns(3)
        search_text = col1.text_input("Search message")
        event_options = sorted(logs_df["event_id"].dropna().unique().tolist())
        selected_event = col2.selectbox("Filter by Event ID", ["All"] + event_options)
        usernames = sorted(logs_df["username"].dropna().unique().tolist())
        selected_user = col3.selectbox("Filter by Username", ["All"] + usernames)

        filtered = logs_df.copy()
        if search_text:
            filtered = filtered[
                filtered["message"].str.contains(search_text, case=False, na=False)
            ]
        if selected_event != "All":
            filtered = filtered[filtered["event_id"] == selected_event]
        if selected_user != "All":
            filtered = filtered[filtered["username"] == selected_user]

        st.dataframe(
            filtered[
                [
                    "timestamp",
                    "event_id",
                    "username",
                    "computer_name",
                    "message",
                ]
            ].head(500),
            use_container_width=True,
        )

    def _render_ai_section(self, alerts_df: pd.DataFrame) -> None:
        st.subheader("AI Security Analyst")
        if alerts_df.empty:
            st.info("AI analysis appears here after alerts are generated.")
            return

        ai_columns = [
            "timestamp",
            "severity",
            "title",
            "ai_summary",
            "ai_mitre_mapping",
            "ai_recommended_remediation",
        ]
        ai_df = alerts_df[ai_columns].dropna(
            subset=["ai_summary", "ai_mitre_mapping", "ai_recommended_remediation"],
            how="all",
        )
        if ai_df.empty:
            st.info("No AI analysis has been stored yet.")
            return

        for _, row in ai_df.head(10).iterrows():
            label = (
                f"{row['severity']} - {row['title']} - "
                f"{self._format_timestamp(row['timestamp'])}"
            )
            with st.expander(label):
                st.markdown(f"**AI Summary:** {row.get('ai_summary') or 'N/A'}")
                st.markdown(
                    f"**MITRE Technique:** {row.get('ai_mitre_mapping') or 'N/A'}",
                )
                st.markdown(
                    "**Response Recommendations:** "
                    f"{row.get('ai_recommended_remediation') or 'N/A'}",
                )

    @staticmethod
    def _format_timestamp(value: object) -> str:
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value)


def main() -> None:
    """Streamlit entry point."""
    db = init_db()
    SIEMDashboard(db).render()


if __name__ == "__main__":
    main()
