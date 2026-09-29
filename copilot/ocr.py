"""Screenshot / photo -> text with Apple's Vision framework. No language model is involved.

An analyst often has tool output only as a picture: a screenshot pasted into a ticket, a phone photo
of a console. Vision's text recognizer transcribes it literally enough for the deterministic
detectors to work on (hex runs, base64, pipe names come through as written); a language model
"reading" the image paraphrases and invents. So this path never involves a language model: Vision -> text ->
`triage`. Transcription is still best-effort OCR -- a blurry photo can drop or swap a character --
so the analyst reads the text before relying on a verdict built on it.

Requires the `pyobjc-framework-Vision` binding (installed by requirements.txt) and macOS; on other
systems `ocr()` raises OCRUnavailable with a plain explanation. EXIF orientation is honoured, so a
portrait phone photo is read the way it is displayed.
"""


class OCRUnavailable(RuntimeError):
    """Vision.framework cannot be used here (not macOS, binding missing, unreadable image)."""


def _load():
    try:
        import Quartz  # noqa: F401
        import Vision  # noqa: F401
        from Foundation import NSURL  # noqa: F401
    except ImportError as e:
        raise OCRUnavailable(f"Vision framework binding not available ({e}); install pyobjc-framework-Vision on macOS")


def _orientation(source):
    """The image's EXIF/TIFF orientation (1 when absent), so text in a rotated photo is read upright."""
    import Quartz
    props = Quartz.CGImageSourceCopyPropertiesAtIndex(source, 0, None) or {}
    value = props.get(Quartz.kCGImagePropertyOrientation)
    try:
        return int(value) if value else 1
    except (TypeError, ValueError):
        return 1


def ocr(image_path, language_correction=False):
    """Recognized text lines, top to bottom, as one string. `language_correction` stays off by default
    so hex bytes, hashes and encoded blobs are transcribed as seen rather than 'corrected'."""
    _load()
    import Quartz
    import Vision
    from Foundation import NSURL

    url = NSURL.fileURLWithPath_(str(image_path))
    source = Quartz.CGImageSourceCreateWithURL(url, None)
    if source is None:
        raise OCRUnavailable(f"cannot read image {image_path}")
    image = Quartz.CGImageSourceCreateImageAtIndex(source, 0, None)
    if image is None:
        raise OCRUnavailable(f"no decodable image in {image_path}")
    request = Vision.VNRecognizeTextRequest.alloc().init()
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    request.setUsesLanguageCorrection_(bool(language_correction))
    handler = Vision.VNImageRequestHandler.alloc().initWithCGImage_orientation_options_(image, _orientation(source), None)
    ok, err = handler.performRequests_error_([request], None)
    if not ok:
        raise OCRUnavailable(f"text recognition failed: {err}")
    observations = list(request.results() or [])
    # Vision's coordinates have the origin at the bottom-left; sort by descending y = top to bottom.
    observations.sort(key=lambda o: -o.boundingBox().origin.y)
    lines = []
    for obs in observations:
        cands = obs.topCandidates_(1)
        if cands and len(cands):
            lines.append(str(cands[0].string()))
    return "\n".join(lines)
