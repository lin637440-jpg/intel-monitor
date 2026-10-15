from setuptools import setup, find_packages

setup(
    name="intel-monitor",
    version="1.0.0",
    description="AI Security Intelligence - Monitor & Enrichment Module",
    author="A",
    packages=find_packages(
        exclude=["venv", "venv.*", "tests", "tests.*"]
    ),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "lxml",
        "python-dotenv",
        "APScheduler",
        "sentence-transformers",
        "pydantic",
        "networkx",
        "pandas",
        "plotly",
        "streamlit",
        "fastapi",
        "uvicorn",
    ],
    python_requires=">=3.11",
)