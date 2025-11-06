"""
Tika Test Suite
===============
Tests the tika plugin against different file types.

"""

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_tika.main import AzulPluginTika


class TestTikaIntegration(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginTika

    def test_on_attachments_good(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "c5a4af7c8ec74631515504089caafa72be4eb89f88c16fa8f2b4c363a9c8e645",
                        "Zip file iwth a normal attachment.",
                    ),
                )
            ],
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="c5a4af7c8ec74631515504089caafa72be4eb89f88c16fa8f2b4c363a9c8e645",
                        features={
                            "file_metadata": [
                                FV("ISO-8859-1", label="X-TIKA:detectedEncoding"),
                                FV("UniversalEncodingDetector", label="X-TIKA:encodingDetector"),
                            ],
                            "mime": [FV("application/zip")],
                        },
                    ),
                    Event(
                        sha256="bd6d851ac0d22e81d7d21ce34c9151842ee2d56ef25b068a48f6df4c025c76af",
                        parent=EventParent(sha256="c5a4af7c8ec74631515504089caafa72be4eb89f88c16fa8f2b4c363a9c8e645"),
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="bd6d851ac0d22e81d7d21ce34c9151842ee2d56ef25b068a48f6df4c025c76af",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("0/atmosphere/atm_pbr_dusk/atm_pbr_dusk_openworld.atmosphere")]},
                    ),
                    Event(
                        sha256="bc0fec5c1905daed40f7d3bfcea22aa3f84c536bcd5c2309493061ac52688ad4",
                        parent=EventParent(sha256="c5a4af7c8ec74631515504089caafa72be4eb89f88c16fa8f2b4c363a9c8e645"),
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="bc0fec5c1905daed40f7d3bfcea22aa3f84c536bcd5c2309493061ac52688ad4",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("info.json")]},
                    ),
                ],
                data={
                    "bd6d851ac0d22e81d7d21ce34c9151842ee2d56ef25b068a48f6df4c025c76af": b"",
                    "bc0fec5c1905daed40f7d3bfcea22aa3f84c536bcd5c2309493061ac52688ad4": b"",
                },
            ),
        )

    def test_on_attachments_bad(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0327485cc53e3ce118b2842bdf4b74cd00bad6daca474b0a5c0b9d61238196a6", "Benign Zip file."
                    ),
                )
            ],
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="0327485cc53e3ce118b2842bdf4b74cd00bad6daca474b0a5c0b9d61238196a6",
                        features={"mime": [FV("application/gzip")]},
                    ),
                    Event(
                        sha256="c738c605804621aa37e15747b3433269253d9084cdd2f1b4315a9cee82e4f85c",
                        parent=EventParent(sha256="0327485cc53e3ce118b2842bdf4b74cd00bad6daca474b0a5c0b9d61238196a6"),
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="c738c605804621aa37e15747b3433269253d9084cdd2f1b4315a9cee82e4f85c",
                                label="content",
                            )
                        ],
                    ),
                ],
                data={"c738c605804621aa37e15747b3433269253d9084cdd2f1b4315a9cee82e4f85c": b""},
            ),
        )

    def test_on_malicious_pdf(self):
        """Test execute on pdf doc for metadata and augmented stream extraction."""

        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "aed1341128535139314907c41ad52432185880ce62c8073363f3b466d46aa5c5", "Malicious PDF."
                    ),
                )
            ],
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="aed1341128535139314907c41ad52432185880ce62c8073363f3b466d46aa5c5",
                        data=[
                            EventData(
                                hash="bc0a59347f06cb4694df028206e5cb2cf534522bd79532896128e80340b74523", label="text"
                            )
                        ],
                        features={
                            "file_metadata": [
                                FV("0", label="pdf:num3DAnnotations"),
                                FV("0", label="pdf:ocrPageCount"),
                                FV("0", label="pdf:totalUnmappedUnicodeChars"),
                                FV("0", label="pdf:unmappedUnicodeCharsPerPage"),
                                FV("0.0", label="pdf:overallPercentageUnmappedUnicodeChars"),
                                FV("0001-0000", label="pdf:annotationTypes"),
                                FV("0001-0001", label="pdf:annotationTypes"),
                                FV("0004-0000", label="pdf:annotationTypes"),
                                FV("0004-0001", label="pdf:annotationTypes"),
                                FV("0004-0002", label="pdf:annotationTypes"),
                                FV("0004-0003", label="pdf:annotationTypes"),
                                FV("0004-0004", label="pdf:annotationTypes"),
                                FV("0004-0005", label="pdf:annotationTypes"),
                                FV("0004-0006", label="pdf:annotationTypes"),
                                FV("0004-0007", label="pdf:annotationTypes"),
                                FV("0004-0008", label="pdf:annotationTypes"),
                                FV("0004-0009", label="pdf:annotationTypes"),
                                FV("0004-0010", label="pdf:annotationTypes"),
                                FV("1.7", label="pdf:PDFVersion"),
                                FV("2021-06-27T17:39:21Z", label="dcterms:created"),
                                FV("2021-06-27T17:39:21Z", label="dcterms:modified"),
                                FV("2021-06-27T17:39:21Z", label="pdf:docinfo:created"),
                                FV("2021-06-27T17:39:21Z", label="pdf:docinfo:modified"),
                                FV("2021-06-27T17:39:21Z", label="xmp:CreateDate"),
                                FV("2021-06-27T17:39:21Z", label="xmp:MetadataDate"),
                                FV("2021-06-27T17:39:21Z", label="xmp:ModifyDate"),
                                FV("2142", label="pdf:charsPerPage"),
                                FV("37", label="pdf:charsPerPage"),
                                FV("4", label="xmpTPg:NPages"),
                                FV("4553", label="pdf:charsPerPage"),
                                FV("5912", label="pdf:charsPerPage"),
                                FV("False", label="pdf:docinfo:trapped"),
                                FV("Link", label="pdf:annotationSubtypes"),
                                FV("PDF Master 1.0.1", label="pdf:docinfo:producer"),
                                FV("PDF Master 1.0.1", label="pdf:producer"),
                                FV("PDF Master 1.0.1", label="xmp:pdf:Producer"),
                                FV("Ultimate Maps Downloader 481", label="dc:title"),
                                FV("Ultimate Maps Downloader 481", label="pdf:docinfo:title"),
                                FV("Ultimate Maps Downloader 481", label="xmp:dc:title"),
                                FV("application/pdf; version=1.7", label="dc:format"),
                                FV("derolaqu", label="dc:creator"),
                                FV("derolaqu", label="dc:subject"),
                                FV("derolaqu", label="meta:keyword"),
                                FV("derolaqu", label="pdf:docinfo:creator"),
                                FV("derolaqu", label="pdf:docinfo:creator_tool"),
                                FV("derolaqu", label="pdf:docinfo:keywords"),
                                FV("derolaqu", label="xmp:CreatorTool"),
                                FV("derolaqu", label="xmp:dc:creator"),
                                FV("derolaqu", label="xmp:dc:subject"),
                                FV("derolaqu", label="xmp:pdf:Keywords"),
                                FV("false", label="pdf:containsDamagedFont"),
                                FV("false", label="pdf:encrypted"),
                                FV("false", label="pdf:hasCollection"),
                                FV("false", label="pdf:hasMarkedContent"),
                                FV("false", label="pdf:hasXFA"),
                                FV("true", label="access_permission:assemble_document"),
                                FV("true", label="access_permission:can_modify"),
                                FV("true", label="access_permission:can_print"),
                                FV("true", label="access_permission:can_print_faithful"),
                                FV("true", label="access_permission:extract_content"),
                                FV("true", label="access_permission:extract_for_accessibility"),
                                FV("true", label="access_permission:fill_in_form"),
                                FV("true", label="access_permission:modify_annotations"),
                                FV("true", label="pdf:containsNonEmbeddedFont"),
                                FV("true", label="pdf:hasXMP"),
                                FV("uuid:25052966-d025-ed9f-8abe-e42a614362d8", label="xmpMM:DocumentID"),
                            ],
                            "mime": [FV("application/pdf")],
                        },
                    )
                ],
                data={"bc0a59347f06cb4694df028206e5cb2cf534522bd79532896128e80340b74523": b""},
            ),
        )

    def test_encrypted_zip(self):
        """Test an encrypted zip file can be identified."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0083bc74d470535650eae315dc33573c8188b4d6942522d4fc4749825a521fd1", "Encrypted zip file."
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="0083bc74d470535650eae315dc33573c8188b4d6942522d4fc4749825a521fd1",
                        data=[
                            EventData(
                                hash="c5c8db36489e3897d5466e774f7c048a28a11f2b4f617183f236c76cd2cddb8f", label="text"
                            )
                        ],
                        features={
                            "file_metadata": [
                                FV("ISO-8859-1", label="X-TIKA:detectedEncoding"),
                                FV("UniversalEncodingDetector", label="X-TIKA:encodingDetector"),
                            ],
                            "mime": [FV("application/zip")],
                        },
                    )
                ],
                data={"c5c8db36489e3897d5466e774f7c048a28a11f2b4f617183f236c76cd2cddb8f": b""},
            ),
        )

    def test_trigger_tesseract(self):
        """Test a sample that triggers tika's tesseract behaviour.

        This happens on PDFs and word documents with embedded content.

        Note this takes about 90seconds with tesseract enabled and 4seconds if it's disabled.
        The difference in features is nearly none, however no child file will be extracted if you disable tesseract.

        We can disable tesseract in the tika server if this takes too long.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f4d98d0c76ba42afb43e87946dfc87ca411a5d3e05cbfa36380fadf4c5c3524a", "Benign PDF."
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="f4d98d0c76ba42afb43e87946dfc87ca411a5d3e05cbfa36380fadf4c5c3524a",
                        data=[
                            EventData(
                                hash="3051daede48c224e04c679516f686ebad6f653a08314037a18afda9e31a09f68", label="text"
                            )
                        ],
                        features={
                            "file_metadata": [
                                FV("0", label="pdf:charsPerPage"),
                                FV("0", label="pdf:num3DAnnotations"),
                                FV("0", label="pdf:totalUnmappedUnicodeChars"),
                                FV("0", label="pdf:unmappedUnicodeCharsPerPage"),
                                FV("1.5", label="pdf:PDFVersion"),
                                FV("2023-05-17T12:34:54Z", label="dcterms:created"),
                                FV("2023-05-17T12:34:54Z", label="pdf:docinfo:created"),
                                FV("2023-05-17T12:34:54Z", label="xmp:CreateDate"),
                                FV("2023-05-17T12:34:55Z", label="dcterms:modified"),
                                FV("2023-05-17T12:34:55Z", label="pdf:docinfo:modified"),
                                FV("2023-05-17T12:34:55Z", label="xmp:MetadataDate"),
                                FV("2023-05-17T12:34:55Z", label="xmp:ModifyDate"),
                                FV("24", label="pdf:ocrPageCount"),
                                FV("24", label="xmpTPg:NPages"),
                                FV(
                                    "Adobe Photoshop for Macintosh -- Image Conversion Plug-in",
                                    label="pdf:docinfo:producer",
                                ),
                                FV("Adobe Photoshop for Macintosh -- Image Conversion Plug-in", label="pdf:producer"),
                                FV(
                                    "Adobe Photoshop for Macintosh -- Image Conversion Plug-in",
                                    label="xmp:pdf:Producer",
                                ),
                                FV("PDF Presentation Adobe Photoshop ", label="pdf:docinfo:creator_tool"),
                                FV("PDF Presentation Adobe Photoshop ", label="xmp:CreatorTool"),
                                FV("application/pdf; version=1.5", label="dc:format"),
                                FV("false", label="pdf:containsDamagedFont"),
                                FV("false", label="pdf:containsNonEmbeddedFont"),
                                FV("false", label="pdf:encrypted"),
                                FV("false", label="pdf:hasCollection"),
                                FV("false", label="pdf:hasMarkedContent"),
                                FV("false", label="pdf:hasXFA"),
                                FV("true", label="access_permission:assemble_document"),
                                FV("true", label="access_permission:can_modify"),
                                FV("true", label="access_permission:can_print"),
                                FV("true", label="access_permission:can_print_faithful"),
                                FV("true", label="access_permission:extract_content"),
                                FV("true", label="access_permission:extract_for_accessibility"),
                                FV("true", label="access_permission:fill_in_form"),
                                FV("true", label="access_permission:modify_annotations"),
                                FV("true", label="pdf:hasXMP"),
                                FV("uuid:17ea4678-3fc7-5f4d-a395-278dbe0c4f9a", label="xmpMM:DocumentID"),
                            ],
                            "mime": [FV("application/pdf")],
                        },
                    )
                ],
                data={"3051daede48c224e04c679516f686ebad6f653a08314037a18afda9e31a09f68": b""},
            ),
        )

    def test_png_raw_content_exception(self):
        """Tests a stream exception can be handled and the bad metadata removed metadata too long causing errors.

        The metadata removed is in the key "X-TIKA:EXCEPTION:embedded_stream_exception"
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "10c2e5b8731ac604ea26375200927523a524566f61151a0e7877af246e00f4e1", "Benign PNG."
                    ),
                )
            ],
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="10c2e5b8731ac604ea26375200927523a524566f61151a0e7877af246e00f4e1",
                        features={
                            "dropped_metadata": [
                                FV(
                                    "keyword=Raw profile type exif, compressionMethod=deflate, text=exif\n    7042\n45786966000049492a00080",
                                    label="zTXt zTXtEntry",
                                ),
                                FV(
                                    "keyword=Raw profile type exif, value=exif\n    7042\n45786966000049492a00080000000a0000010400010000002",
                                    label="Text TextEntry",
                                ),
                            ],
                            "file_metadata": [
                                FV("0.35273367", label="Dimension HorizontalPixelSize"),
                                FV("0.35273367", label="Dimension VerticalPixelSize"),
                                FV("1", label="Compression NumProgressiveScans"),
                                FV("1", label="imagereader:NumImages"),
                                FV("1.0", label="Dimension PixelAspectRatio"),
                                FV("4", label="Chroma NumChannels"),
                                FV("40", label="height"),
                                FV("40", label="tiff:ImageLength"),
                                FV("40", label="tiff:ImageWidth"),
                                FV("40", label="width"),
                                FV("8 8 8 8", label="Data BitsPerSample"),
                                FV("8 8 8 8", label="tiff:BitsPerSample"),
                                FV("Normal", label="Dimension ImageOrientation"),
                                FV("PixelInterleaved", label="Data PlanarConfiguration"),
                                FV("RGB", label="Chroma ColorSpaceType"),
                                FV("UnsignedIntegral", label="Data SampleFormat"),
                                FV("deflate", label="Compression CompressionTypeName"),
                                FV("image/ocr-png", label="Content-Type-Parser-Override"),
                                FV(
                                    'keyword=XML:com.adobe.xmp, compressionFlag=false, compressionMethod=0, languageTag=, translatedKeyword=, text=<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>\n<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 4.4.0-Exiv2">\n <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n  <rdf:Description rdf:about=""\n    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"\n    xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#"\n    xmlns:dc="http://purl.org/dc/elements/1.1/"\n    xmlns:GIMP="http://www.gimp.org/xmp/"\n    xmlns:tiff="http://ns.adobe.com/tiff/1.0/"\n    xmlns:xmp="http://ns.adobe.com/xap/1.0/"\n   xmpMM:DocumentID="gimp:docid:gimp:db14d8c5-939b-44cd-a81e-6a4780dab565"\n   xmpMM:InstanceID="xmp.iid:e7329aed-f175-4f49-b9a3-e39800c0eef0"\n   xmpMM:OriginalDocumentID="xmp.did:851a3899-b594-4819-956c-0e931f5a91cb"\n   dc:Format="image/png"\n   GIMP:API="2.0"\n   GIMP:Platform="Windows"\n   GIMP:TimeStamp="1651955605860568"\n   GIMP:Version="2.10.30"\n   tiff:Orientation="1"\n   xmp:CreatorTool="GIMP 2.10">\n   <xmpMM:History>\n    <rdf:Seq>\n     <rdf:li\n      stEvt:action="saved"\n      stEvt:changed="/"\n      stEvt:instanceID="xmp.iid:1fd2f231-9093-4d8a-a105-33391a121c0a"\n      stEvt:softwareAgent="Gimp 2.10 (Windows)"\n      stEvt:when="2022-05-07T15:33:25"/>\n    </rdf:Seq>\n   </xmpMM:History>\n  </rdf:Description>\n </rdf:RDF>\n</x:xmpmeta>\n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                           \n<?xpacket end="w"?>',
                                    label="iTXt iTXtEntry",
                                ),
                                FV(
                                    'keyword=XML:com.adobe.xmp, value=<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>\n<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 4.4.0-Exiv2">\n <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n  <rdf:Description rdf:about=""\n    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"\n    xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#"\n    xmlns:dc="http://purl.org/dc/elements/1.1/"\n    xmlns:GIMP="http://www.gimp.org/xmp/"\n    xmlns:tiff="http://ns.adobe.com/tiff/1.0/"\n    xmlns:xmp="http://ns.adobe.com/xap/1.0/"\n   xmpMM:DocumentID="gimp:docid:gimp:db14d8c5-939b-44cd-a81e-6a4780dab565"\n   xmpMM:InstanceID="xmp.iid:e7329aed-f175-4f49-b9a3-e39800c0eef0"\n   xmpMM:OriginalDocumentID="xmp.did:851a3899-b594-4819-956c-0e931f5a91cb"\n   dc:Format="image/png"\n   GIMP:API="2.0"\n   GIMP:Platform="Windows"\n   GIMP:TimeStamp="1651955605860568"\n   GIMP:Version="2.10.30"\n   tiff:Orientation="1"\n   xmp:CreatorTool="GIMP 2.10">\n   <xmpMM:History>\n    <rdf:Seq>\n     <rdf:li\n      stEvt:action="saved"\n      stEvt:changed="/"\n      stEvt:instanceID="xmp.iid:1fd2f231-9093-4d8a-a105-33391a121c0a"\n      stEvt:softwareAgent="Gimp 2.10 (Windows)"\n      stEvt:when="2022-05-07T15:33:25"/>\n    </rdf:Seq>\n   </xmpMM:History>\n  </rdf:Description>\n </rdf:RDF>\n</x:xmpmeta>\n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                                                                                                    \n                           \n<?xpacket end="w"?>, language=, compression=none',
                                    label="Text TextEntry",
                                ),
                                FV("nonpremultipled", label="Transparency Alpha"),
                                FV(
                                    "pixelsPerUnitXAxis=2835, pixelsPerUnitYAxis=2835, unitSpecifier=meter",
                                    label="pHYs",
                                ),
                                FV("profileName=ICC profile, compressionMethod=deflate", label="iCCP"),
                                FV("red=255, green=255, blue=255", label="Chroma BackgroundColor"),
                                FV("red=255, green=255, blue=255", label="bKGD bKGD_RGB"),
                                FV("true", label="Chroma BlackIsZero"),
                                FV("true", label="Compression Lossless"),
                                FV(
                                    "width=40, height=40, bitDepth=8, colorType=RGBAlpha, compressionMethod=deflate, filterMethod=adaptive, interlaceMethod=none",
                                    label="IHDR",
                                ),
                                FV(
                                    "year=2022, month=5, day=7, hour=20, minute=33, second=25",
                                    label="Document ImageModificationTime",
                                ),
                                FV("year=2022, month=5, day=7, hour=20, minute=33, second=25", label="tIME"),
                            ],
                            "mime": [FV("image/png")],
                        },
                    )
                ],
            ),
        )

    def test_jpg(self):
        """Tests a stream exception can be handled and the bad metadata removed metadata too long causing errors.

        (JPG example)
        The metadata removed is in the key "X-TIKA:EXCEPTION:embedded_stream_exception"
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a1abb1445a39dc424fab2eaeb44cd2741853801f3a2c72a63401ab18ed4d0513", "JPG file."
                    ),
                )
            ],
        )
        # Drop fields that change too often.
        result.events[0].features["file_metadata"] = [
            f for f in result.events[0].features["file_metadata"] if f.label not in ["File Modified Date", "File Name"]
        ]
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="a1abb1445a39dc424fab2eaeb44cd2741853801f3a2c72a63401ab18ed4d0513",
                        features={
                            "dropped_metadata": [
                                FV(
                                    "0.0, 0.0000763, 0.0001526, 0.0002289, 0.0003052, 0.0003815, 0.0004578, 0.0005341, 0.0006104, 0.00068",
                                    label="ICC:Blue TRC",
                                ),
                                FV(
                                    "0.0, 0.0000763, 0.0001526, 0.0002289, 0.0003052, 0.0003815, 0.0004578, 0.0005341, 0.0006104, 0.00068",
                                    label="ICC:Green TRC",
                                ),
                                FV(
                                    "0.0, 0.0000763, 0.0001526, 0.0002289, 0.0003052, 0.0003815, 0.0004578, 0.0005341, 0.0006104, 0.00068",
                                    label="ICC:Red TRC",
                                ),
                            ],
                            "file_metadata": [
                                FV("(0, 0, 0)", label="ICC:Media Black Point"),
                                FV("(0.1431, 0.0606, 0.7141)", label="ICC:Blue Colorant"),
                                FV("(0.3851, 0.7169, 0.0971)", label="ICC:Green Colorant"),
                                FV("(0.4361, 0.2225, 0.0139)", label="ICC:Red Colorant"),
                                FV("(0.9505, 1, 1.0891)", label="ICC:Media White Point"),
                                FV("(76.0365, 80, 87.1246)", label="ICC:Luminance"),
                                FV("0", label="Flags 1"),
                                FV("0", label="URL List"),
                                FV("0 0 0 0", label="Layers Group Information"),
                                FV("0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", label="Caption Digest"),
                                FV("0 0 0 0 0 0 0 0 1", label="Print Flags"),
                                FV("0 0 0 1 0 0 2 64 0 0 2 64 0 0 0 0", label="Grid and Guides Information"),
                                FV("0 1", label="Layer State Information"),
                                FV("0 1 0 0 0 0 0 0 0 2", label="Print Flags Information"),
                                FV("0 1 0 0 0 2", label="Layer Selection IDs"),
                                FV("0.964 1 0.825", label="ICC:XYZ values"),
                                FV("1", label="tiff:Orientation"),
                                FV("1 (Adobe Photoshop, Adobe Photoshop CS5.1) 1", label="Version Info"),
                                FV("1 1", label="Layer Groups Enabled ID"),
                                FV("1.0", label="Pixel Aspect Ratio"),
                                FV("1074 bytes", label="Exif Thumbnail:Thumbnail Length"),
                                FV("112", label="tiff:ImageLength"),
                                FV("112 pixels", label="Exif SubIFD:Exif Image Height"),
                                FV("112 pixels", label="Image Height"),
                                FV("12 (Maximum), Standard format, 3 scans", label="JPEG Quality"),
                                FV("120", label="Global Angle"),
                                FV("14219 bytes", label="File Size"),
                                FV("17", label="ICC:Tag Count"),
                                FV(
                                    "1931 2° Observer, Backing (0, 0, 0), Geometry Unknown, Flare 1%, Illuminant D65",
                                    label="ICC:Measurement",
                                ),
                                FV("1998:02:09 06:49:00", label="ICC:Profile Date/Time"),
                                FV("2", label="Seed Number"),
                                FV("2.1.0", label="ICC:Version"),
                                FV("20", label="XMP Value Count"),
                                FV("2015-05-08T10:32:14", label="dcterms:created"),
                                FV("2015-05-08T10:32:14", label="dcterms:modified"),
                                FV("2015:05:08 10:32:14", label="Exif IFD0:Date/Time"),
                                FV("25600", label="DCT Encode Version"),
                                FV("3", label="Number of Components"),
                                FV("30", label="Global Altitude"),
                                FV("308 bytes", label="Exif Thumbnail:Thumbnail Offset"),
                                FV("3144", label="ICC:Profile Size"),
                                FV("4 Huffman tables", label="Number of Tables"),
                                FV("64", label="Flags 0"),
                                FV("72 dots per inch", label="Exif IFD0:X Resolution"),
                                FV("72 dots per inch", label="Exif IFD0:Y Resolution"),
                                FV("72 dots per inch", label="Exif Thumbnail:X Resolution"),
                                FV("72 dots per inch", label="Exif Thumbnail:Y Resolution"),
                                FV("72.0", label="tiff:XResolution"),
                                FV("72.0", label="tiff:YResolution"),
                                FV("72x72 DPI", label="Resolution Info"),
                                FV("8", label="tiff:BitsPerSample"),
                                FV("8 bits", label="Data Precision"),
                                FV("90", label="tiff:ImageWidth"),
                                FV("90 pixels", label="Exif SubIFD:Exif Image Width"),
                                FV("90 pixels", label="Image Width"),
                                FV("Adobe Photoshop CS5.1 Windows", label="Exif IFD0:Software"),
                                FV("Adobe Photoshop CS5.1 Windows", label="tiff:Software"),
                                FV("Baseline", label="Compression Type"),
                                FV("CRT", label="ICC:Technology"),
                                FV(
                                    "Cb component: Quantization table 1, Sampling factors 1 horiz/1 vert",
                                    label="Component 2",
                                ),
                                FV("Centered, Scale 1.0", label="Print Scale"),
                                FV("Copyright (c) 1998 Hewlett-Packard Company", label="ICC:Profile Copyright"),
                                FV(
                                    "Cr component: Quantization table 1, Sampling factors 1 horiz/1 vert",
                                    label="Component 3",
                                ),
                                FV("Display Device", label="ICC:Class"),
                                FV("IEC", label="ICC:Device manufacturer"),
                                FV(
                                    "IEC 61966-2.1 Default RGB colour space - sRGB",
                                    label="ICC:Device Model Description",
                                ),
                                FV("IEC http://www.iec.ch", label="ICC:Device Mfg Description"),
                                FV("Inch", label="Exif IFD0:Resolution Unit"),
                                FV("Inch", label="Exif Thumbnail:Resolution Unit"),
                                FV("Inch", label="tiff:ResolutionUnit"),
                                FV("JPEG (old-style)", label="Exif Thumbnail:Compression"),
                                FV(
                                    "JpegRGB, 90x112, Decomp 30464 bytes, 1572865 bpp, 1074 bytes",
                                    label="Thumbnail Data",
                                ),
                                FV("Lino", label="ICC:CMM Type"),
                                FV("Microsoft Corporation", label="ICC:Primary Platform"),
                                FV("RGB", label="ICC:Color space"),
                                FV(
                                    "Reference Viewing Condition in IEC61966-2.1",
                                    label="ICC:Viewing Conditions Description",
                                ),
                                FV("Top, left side (Horizontal / normal)", label="Exif IFD0:Orientation"),
                                FV("XYZ", label="ICC:Profile Connection Space"),
                                FV(
                                    "Y component: Quantization table 0, Sampling factors 1 horiz/1 vert",
                                    label="Component 1",
                                ),
                                FV("YCbCr", label="Color Transform"),
                                FV("[112 values]", label="Color Transfer Functions"),
                                FV("[171 values]", label="Print Info 2"),
                                FV("[434 values]", label="Print Style"),
                                FV("[72 values]", label="Color Halftoning Information"),
                                FV("acsp", label="ICC:Signature"),
                                FV("image/ocr-jpeg", label="Content-Type-Parser-Override"),
                                FV("sRGB", label="Exif SubIFD:Color Space"),
                                FV("sRGB", label="ICC:Device model"),
                                FV("sRGB IEC61966-2.1", label="ICC:Profile Description"),
                                FV("view (0x76696577): 36 bytes", label="ICC:Viewing Conditions"),
                                FV("xmp.did:17ACF1BC18F5E41186DCECFA30DBF83A", label="xmpMM:DocumentID"),
                                FV("제목 없음-2 (0,0,112,90) 1 Slices", label="Slices"),
                            ],
                            "mime": [FV("image/jpeg")],
                        },
                    )
                ],
            ),
        )

    def test_xarchive(self):
        """Test opt-out on unknown archive file."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "ba28ef810fd63106b3bca61821b62c93274cddcb69a927fdfdfbcd1949c71b6f",
                        "xarchive, probably extracted from another plugin.",
                    ),
                )
            ],
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))

    def test_on_corrupted_zip(self):
        """Test executing on corrupt file does not cause errors."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "26fe4537855d5afd036e77e042a735e80cc611653255b5a1cf75e065fa20ce8e",
                        "Benign corrupted zip file.",
                    ),
                )
            ],
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))

    def test_on_apk(self):
        """Test skipping blacklisted content types."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "7c33a3c691d9e0648f1a10e0f518ba208cab1430b1bf80c06bc1ca26971b973d",
                        "Gustuff android malware file.",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))
