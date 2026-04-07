#!/usr/bin/env python3
"""Netflix MSL Client — エントリポイント (src/netflix_msl パッケージへの委譲)"""

import sys
from pathlib import Path

# src/ をモジュール検索パスに追加
sys.path.insert(0, str(Path(__file__).parent / "src"))

from netflix_msl.__main__ import main

if __name__ == "__main__":
    main()
