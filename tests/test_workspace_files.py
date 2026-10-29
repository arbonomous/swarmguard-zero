import io,tarfile,tempfile,unittest
from pathlib import Path
import workspace_files as wf

class TransferTests(unittest.TestCase):
    def test_source_roundtrip(self):
        files={'src/main.py':b'print(1)\n','README.md':b'Example'}
        self.assertEqual(wf.read_archive(wf.make_archive(files)),files)
    def test_private_paths_rejected(self):
        for name in ['../x.py','/x.py','.env','src/.env.txt','.ssh/key.txt','credentials.json','foo\\bar.py','src/../a.py']:
            with self.subTest(name=name),self.assertRaises(ValueError):wf.validate_files({name:b'a'})
    def test_secret_content_rejected(self):
        with self.assertRaises(ValueError):wf.validate_files({'config.py':b'API_KEY = "abcdefghijk123456789"'})
    def test_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'x.py').write_text('a');(root/'link.py').symlink_to(root/'x.py')
            with self.assertRaises(ValueError):wf.selected_files(root,['link.py'])
    def test_archive_links_rejected(self):
        b=io.BytesIO()
        with tarfile.open(fileobj=b,mode='w') as t:
            e=tarfile.TarInfo('x.py');e.type=tarfile.SYMTYPE;e.linkname='/etc/passwd';t.addfile(e)
        with self.assertRaises(ValueError):wf.read_archive(b.getvalue())
    def test_duplicate_archive_rejected(self):
        b=io.BytesIO()
        with tarfile.open(fileobj=b,mode='w') as t:
            for n in range(2):
                e=tarfile.TarInfo('x.py');e.size=1;t.addfile(e,io.BytesIO(b'a'))
        with self.assertRaises(ValueError):wf.read_archive(b.getvalue())
    def test_size_rejected(self):
        with self.assertRaises(ValueError):wf.validate_files({'x.py':b'a'*(wf.MAX_FILE+1)})
