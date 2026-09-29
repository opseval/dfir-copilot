"""Vision-framework OCR: no language model, EXIF-aware, literal enough for triage. Skipped where the
binding is missing (non-macOS CI); the CLI guards are tested everywhere."""
import os
import shutil
import subprocess

import pytest

from copilot import cli, ocr

FIXTURE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "copilot", "sample", "ocr_sample.jpg"))
TOKENS = ("173.234.31.186", "POSSIBLE BREAK-IN ATTEMPT", "Invalid user webmaster")


def _vision_available():
    try:
        ocr._load()
        return True
    except ocr.OCRUnavailable:
        return False


needs_vision = pytest.mark.skipif(not _vision_available(), reason="Vision.framework binding not available")


@needs_vision
def test_fixture_transcribes_the_indicators():
    text = ocr.ocr(FIXTURE)
    for token in TOKENS:
        assert token in text, text


@needs_vision
def test_lines_come_out_top_to_bottom():
    text = ocr.ocr(FIXTURE)
    assert text.index("POSSIBLE BREAK-IN") < text.index("Invalid user webmaster")


@needs_vision
def test_exif_rotated_photo_is_read_upright(tmp_path):
    """A portrait phone photo stores the pixels sideways plus an EXIF orientation tag; Vision must be
    told the orientation or it reads rotated text as garbage."""
    import Quartz
    from Foundation import NSURL
    sideways = tmp_path / "sideways.jpg"
    subprocess.run(["/usr/bin/sips", "--rotate", "270", FIXTURE, "--out", str(sideways)], check=True, capture_output=True)
    src = Quartz.CGImageSourceCreateWithURL(NSURL.fileURLWithPath_(str(sideways)), None)
    img = Quartz.CGImageSourceCreateImageAtIndex(src, 0, None)
    tagged = tmp_path / "tagged.jpg"
    dest = Quartz.CGImageDestinationCreateWithURL(NSURL.fileURLWithPath_(str(tagged)), "public.jpeg", 1, None)
    Quartz.CGImageDestinationAddImage(dest, img, {Quartz.kCGImagePropertyOrientation: 6})   # 6 = rotate 90° CW to display
    assert Quartz.CGImageDestinationFinalize(dest)
    assert ocr._orientation(Quartz.CGImageSourceCreateWithURL(NSURL.fileURLWithPath_(str(tagged)), None)) == 6
    text = ocr.ocr(str(tagged))
    for token in TOKENS:
        assert token in text, text


@needs_vision
def test_unreadable_image_raises_cleanly(tmp_path):
    with pytest.raises(ocr.OCRUnavailable):
        ocr.ocr(str(tmp_path / "missing.png"))
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image")
    with pytest.raises(ocr.OCRUnavailable):
        ocr.ocr(str(bad))


def test_missing_binding_is_a_plain_error(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_vision(name, *a, **k):
        if name in ("Vision", "Quartz"):
            raise ImportError("no Vision here")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_vision)
    with pytest.raises(ocr.OCRUnavailable, match="pyobjc-framework-Vision"):
        ocr.ocr(FIXTURE)


def test_cli_refuses_to_overwrite_the_input_image(tmp_path, capsys):
    img = tmp_path / "evidence.jpg"
    shutil.copy(FIXTURE, img)
    link = tmp_path / "same.jpg"
    os.symlink(img, link)
    before = img.read_bytes()
    assert cli.main(["ocr", str(img), "-o", str(img)]) == 2
    assert cli.main(["ocr", str(img), "-o", str(link)]) == 2
    assert img.read_bytes() == before, "the evidence image is untouched"
    assert "output path is the input image" in capsys.readouterr().err


def test_cli_reports_unwritable_output(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(ocr, "ocr", lambda path: "some text")           # keep this test binding-independent
    assert cli.main(["ocr", FIXTURE, "-o", str(tmp_path)]) == 2       # a directory is not a writable file
    assert "cannot write" in capsys.readouterr().err
