"""
app 包初始化
把项目根加入 sys.path，让 from collectors / storage / enrichment 等顶层导入能工作
"""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))