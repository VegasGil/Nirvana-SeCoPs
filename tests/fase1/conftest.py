"""Configuración pytest: añade la raíz al sys.path para importar bot1_cerebro.*"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))