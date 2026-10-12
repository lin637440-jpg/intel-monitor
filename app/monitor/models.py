from typing import Any, Optional
from pydantic import BaseModel, Field


class IntelItem(BaseModel):
    """统一情报记录"""
    uid: str
    source: str
    title: str = ""
    description: str = ""
    url: Optional[str] = None
    published: Optional[str] = None

    cvss: Optional[dict] = None
    cvss_full: Optional[dict] = None
    cwe: list[str] = Field(default_factory=list)
    pocs: list[dict] = Field(default_factory=list)
    related_papers: list[dict] = Field(default_factory=list)
    assets: dict = Field(default_factory=dict)
    attack_chain: dict = Field(default_factory=dict)
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    risk_detail: dict = Field(default_factory=dict)
    chain_files: list[str] = Field(default_factory=list)

    raw: Optional[dict] = None


class CollectResult(BaseModel):
    inserted: int
    total: int
    source: str


class SearchResult(BaseModel):
    count: int
    items: list[dict]