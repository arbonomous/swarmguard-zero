"""Frozen logo alpha/identity regressions, not Mac-rendering evidence."""
import unittest
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[1]/'assets'/'brand'
class BrandTests(unittest.TestCase):
    def test_template_is_not_opaque_square(self):
        image=Image.open(ROOT/'swarmguard-icon-menu-template.png').convert('RGBA')
        self.assertEqual(image.size,(44,44))
        alpha=image.getchannel('A')
        self.assertEqual(alpha.getextrema(),(0,255))
        self.assertEqual(alpha.getpixel((0,0)),0)
        self.assertLess(sum(v>0 for v in alpha.getdata()),44*44*.7)
    def test_panel_and_menu_share_same_mark(self):
        a=Image.open(ROOT/'swarmguard-mark.png').convert('RGBA')
        b=Image.open(ROOT/'swarmguard-icon-menu.png').convert('RGBA')
        self.assertEqual(a.tobytes(),b.tobytes())
