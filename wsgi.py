
import os
import sys

PROJECT_DIR = "/home/Andrei7669/vkus-primorya-history"
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from app import app as aiohttp_app
from aiohttp import web
