"""
Tika Test Suite
===============
Tests the tika plugin against different file types.

"""

from unittest import mock

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


def mock_malicious_pdf(*args, **kwargs):
    return MALDOC_RESPONSE


def mock_bad_content(*args, **kwargs):
    return None


def mock_apk_content(*args, **kwargs):
    return {
        "metadata": {
            "Content-Type": "application/vnd.android.package-archive",
            "Foo": "bar",
        },
    }


def mock_xarchive_content(*args, **kwargs):
    return {
        "metadata": {
            "Content-Type": "application/x-archive",
            "Foo": "bar",
        },
    }


def mock_encrypted_zip_content(*args, **kwargs):
    return TEST_ENCRYPTED_ZIP_DATA


def mock_png_content(*args, **kwargs):
    return TEST_PNG_RESPONSE_DATA


class TestTika(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginTika

    @mock.patch("tika.unpack.from_file", side_effect=mock_malicious_pdf)
    def test_on_malicious_pdf(self, mock_unpack):
        """Test execute on pdf doc for metadata and augmented doc extraction."""

        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "aed1341128535139314907c41ad52432185880ce62c8073363f3b466d46aa5c5", "Malicious PDF."
                    ),
                )
            ],
            no_multiprocessing=True,
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
                                FV("Ultimate Maps Downloader 481", label="dc:title"),
                                FV("Ultimate Maps Downloader 481", label="pdf:docinfo:title"),
                                FV("application/pdf; version=1.7", label="dc:format"),
                                FV("derolaqu", label="dc:creator"),
                                FV("derolaqu", label="dc:subject"),
                                FV("derolaqu", label="meta:keyword"),
                                FV("derolaqu", label="pdf:docinfo:creator"),
                                FV("derolaqu", label="pdf:docinfo:creator_tool"),
                                FV("derolaqu", label="pdf:docinfo:keywords"),
                                FV("derolaqu", label="xmp:CreatorTool"),
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

    @mock.patch("tika.unpack.from_file", side_effect=mock_encrypted_zip_content)
    def test_encrypted_zip(self, mock_unpack):
        """Test an encrypted zip file can be identified."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0083bc74d470535650eae315dc33573c8188b4d6942522d4fc4749825a521fd1", "Encrypted zip file."
                    ),
                )
            ],
            no_multiprocessing=True,
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

    @mock.patch("tika.unpack.from_file", side_effect=mock_png_content)
    def test_png_raw_content_exception(self, mock_unpack):
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
            no_multiprocessing=True,
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
                                FV("Mon Apr 07 02:13:43 +00:00 2025", label="File Modified Date"),
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
                                FV("apache-tika-16196145968302569733.tmp", label="File Name"),
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

    @mock.patch("tika.unpack.from_file", side_effect=mock_bad_content)
    def test_on_corrupted_zip(self, mock_unpack):
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
            no_multiprocessing=True,
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))

    @mock.patch("tika.unpack.from_file", side_effect=mock_apk_content)
    def test_on_apk(self, mock_unpack):
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
            ],
            no_multiprocessing=True,
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))

    @mock.patch("tika.unpack.from_file", side_effect=mock_apk_content)
    def test_xarchive(self, mock_unpack):
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
            no_multiprocessing=True,
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))


MALDOC_RESPONSE = {
    "content": "\n \n\n                               1 / 4\n\nhttp://somesatog.blo.gg/2021/march/orca-3d-download-crack.html#ONn=ebYCWfwtGugDH1wA0XwvX4coUqdiYvgzH9gBUD3B==\nhttp://somesatog.blo.gg/2021/march/orca-3d-download-crack.html#ONn=ebYCWfwtGugDH1wA0XwvX4coUqdiYvgzH9gBUD3B==\n\n\n \n\nUltimate Maps Downloader 4.8.1\n\nDownload online maps as tiles and convert them to high-quality image files. ... 4.8.1. Ultimate Maps Downloader. Download map\nimagery, topographic and road .... Version 4.8.1. Fix Conflict with Elementor tabs, ... Fix Conflict with SEO Ultimate plugin and\nbootstrap theme. Version 3.9.2. Fix AJAX dynamic .... Download Ultimate Maps Downloader for Windows to download maps\nfrom Google Maps, Yahoo Maps, Bing Maps, or OpenStreet Maps.. Ultimate Maps Downloader 4.8.1 is free to download from\nour software library. The following versions: 4.8, 4.7 and 4.6 are the most frequently .... Ultimate Maps Downloader افزار نرم یک\nMaps Ultimate .... نقشه برداری حرفه ای و دقیق برای دانلود تصاویر ماهواره ای، نقشه های توپوگرافی و جاده ای از ارائه دهندگان آنلاین مختلف مانند\nDownloader is a detailed mapping software that allows you to download map imagery, topographic and road ... 4.8.1 (See all)..\nAlso Download: Stardock Groupy With Crack (Latest) Stardock WindowFX Full ... DC 2019.012.20040 With Crack Next\nArticle Ultimate Maps Downloader 4.8.1 .... Ultimate Maps Downloader is a detailed mapping software that allows you to\ndownload map imagery, topographic and road maps from various .... Ultimate Maps Downloader 4.8.1 | File size: 56 MB\nUltimate Maps Downloader is a detailed mapping software that allows you to download map ...\n\nDownload VMWARE VCENTER SERVER V5.5.0A-MAGNiTUDE torrent or any ... Vmware ... Ultimate Maps Downloader\n4.8.1 · Dhoom 3 Video .... Download Google Maps, Bing and Yahoo Maps Downloader 4.8.1 Software Ultimate. Ultimate Maps\nDownloader is a mapping application which allows you .... Ultimate Maps Downloader is a reliable mapping application that\nhelps you download map imagery, topographic and road maps from various .... Download offline/online game unlimited mod\napk for Android with HappyMod. Safe, fast and ... Modify unlock all characters, items, maps! New unlock ... Download Rope\nHero: Vice Town V4.8.2 (MOD, Unlimited Money) Mod Apk 4.8.1. Naxeex .... Ultimate Maps Downloader 4.8.1 | 56.1 Mb\nUltimate Maps Downloader is a detailed mapping software that allows you to download map imagery, topographic .... Ultimate\nMaps Downloader 4.8.1 + Activator | 53.53 MB Information: Ultimate Maps Downloader is a detailed mapping software that\nallows you to download ...\n\nultimate maps downloader\n\nultimate maps, ultimate maps downloader, ultimate maps by supsystic wordpress, ultimate maps downloader 4.8.1 crack,\nultimate maps downloader 3.0.1 crack, ultimate maps kit, ultimate maps downloader free download, ultimate maps downloader\n3.0.1, ultimate maps downloader 4.8.1 key, ultimate maps downloader 4.7.2 registration key\n\nUltimate Maps Downloader 4.8.1 Ultimate Maps Downloader 4.8.1 Ultimate Maps Downloader is a detailed mapping software\nthat allows you .... You can find below a few links to other Ultimate Maps Downloader versions: 4.8.1 4.7.2 4.8.0 4.7.1 4.1.0.\nOne of the best SIMPLE action to .... Ultimate Maps Downloader – is a detailed mapping software that allows you to download\nmap imagery, topographic and road maps from various map servers.. app by Lizard Labs crack by me Patched Files (1): Code:-\nUltimate Maps Downloader.exe | 1.44mb Virustotal Scan (Patch File Only) Download .... Ultimate Maps Downloader is a\ndetailed mapping software that allows you to download map imagery, topographic and road maps from various map servers..\nUltimate Maps Downloader | How To DownLoad High Resolution Image. 8,784 views8.7K views. • May 23, 2017.. Main\nnavigation. Menu. Home · Download · News · Online Help · Resources · RSS · Donate · Author. What is Notepad++. Notepad++\nis a free (as in “free .... Ultimate Maps Downloader 4.8.0 | 56.1 MbUltimate Maps Downloader is a detailed mapping software\nthat allows you to download map imagery, topographic .... Maxi 247 Rika > DOWNLOAD. lilya rika maxi dressrikarda maxi\nruha 8ba239ed26 Maxi-247,,,08,,,BridalSP, ... Ultimate Maps Downloader 4.8.1. Ultimate Maps\nDownloader可以非常轻松的从各种地图服务器下载到最新最全面的地图图像和道路地图，这样就可以方便离线进行使用，非常方便 ...\n\nultimate maps downloader 4.8.1 crack\n\nUltimate Maps Downloader is a reliable mapping application that helps you download map imagery, topographic and road maps\nfrom various .... Ultimate Maps Downloader is a detailed mapping software that allows you to download map imagery,\ntopographic and road maps from various map servers.. Ultimate Maps Downloader - Ultimate Maps Downloader can download\nsatellite imagery, topographic and road maps from various map servers. Ready for use it .... Ultimate Maps Downloader is a\n\n                               2 / 4\n\n\n\n \n\ndetailed mapping software that allows you to download map imagery, topographic and road maps from various .... Ultimate\nMaps Downloader 4.8.1 · Software 1年前(2019-08-24) 0评论. Ultimate Maps\nDownloader是一款非常专业的世界地图下载软件，有了这款软件，我们就 ...\n\nultimate maps kit\n\nTo do so, you'll have to complete a series of missions. Like Grand Theft Auto series, the fact that your character can freely roam\nacross the map is a key feature of .... المنتدى في للتسجيل الحاجة دون اعلاناتكم كتابة ميزة فتح تم رغباتكم تلبية في منا رغبة : سارة بشرى\nMaps Ultimate .4.8.1 نسخة كاملة Downloader Maps Ultimate علماً ان هذه الميزة تجريبيه ،،،. لتفعيل العضوية الخاصة بكم .... تحميل برنامج\nDownloader صور تنزيل على يساعدك به موثوق خرائط رسم تطبيق هو .... Ultimate Maps Downloader Crack : is a detailed mapping\nsoftware that allows you to download map imagery, topographic and road maps from.. Ultimate Maps Downloader 4.8.1 | 56.1\nMb Ultimate Maps Downloader is a detailed mapping software that allows you to download map imagery, topographic ....\nUltimate Maps Downloader 4.8.1 | 56.1 Mb Ultimate Maps Downloader is a detailed mapping software that allows you to map\nimagery, .... Ultimate Maps\nDownloader是一款面向世界高清地图资源的地图下载器，可以帮助用户轻松下载地图图像、道路地图等资源，迅速了解地图情况~还能实现离线浏览 .... Ultimate Maps\nDownloader is a professional software application whose purpose is to help you download satellite imagery, topographic and ....\nDownload Ultimate Maps Downloader 4 ✅ Software detailed mapping allows you to download map images, maps terrain and\nroads from the map server other.. Ultimate Maps Downloader 4.8.1 [Latest]. Download Ultimate Maps Downloader. Ultimate\nMaps Downloader is a detailed mapping software .... Download Ultimate Maps Downloader 4.0 free - Top4Download.com\noffers free software downloads for Windows, Mac, iOS and Android computers and mobile ....\nhttps://pixhost.icu/avaxhome/92/75/006a7592_medium.jpg Ultimate Maps Downloader 4.8.1 | 56.1 Mb Ultimate Maps\nDownloader is a detailed mapping .... برنامج تحميل Ultimate Maps Downloader 4.8.1 كاملة نسخة Ultimate Maps Downloader هو\nShare .E19 | 2020 ,12th June .4.8.1 Downloader Maps Ultimate .... تطبيق رسم خرائط موثوق به يساعدك على تنزيل صور الخرائط ، والخرائط\nEmbed Recast Subscribe .... افزار نرم با یاهو و بینگ ، گوگل های نقشه دانلود Ultimate Maps Downloader 4.8.1. 09 گوناگون .1392 دی »\nDownloader Maps Ultimate Mb 56.1 | 4.8.1 Downloader Maps Ultimate .... 46273. دانلود نقشه های گوگل ، بینگ .admin .ابزارهای مفید\nis a detailed mapping software that allows you to download map .... الخرائط صور تنزيل برنامج Ultimate Maps Downloader v.4.8.1\n-地図-ソフトウェアの詳細なマッピングがダウンロードできる地図画像 Downloader Maps Ultimate ..قســم برامـج الكمبيوتر العـامـة\n地形や道路からの地図サーバーその他.. It is an application that one can use to download maps from Google, Yahoo and Microsoft. The user\ninterface of this application is very simple and .... Ultimate Maps Downloader. 4.8.1. Ultimate Maps Downloader. Download map\nimagery, topographic and road maps from various map servers. Offline Map .... Ghost1980 · Aug 24, 2019. Replies: 0. Views:\n83. Aug 24, 2019 · Ghost1980 · Ghost1980. B · App Windows Ultimate Maps Downloader 4.8.1 · BaDshaH · Aug 24 ....\nUltimate Maps Downloader 4.8.1. Ultimate Maps Downloader. В свет вышла новая версия профессиональной программы\nUltimate Maps .... Ultimate Maps Downloader 4.8.1 | 56.1 Mb Ultimate Maps Downloader is a detailed mapping software that\nallows you to download map .... Ultimate Maps Downloader 4.8.1 | 56.1 Mb Ultimate Maps Downloader is a detailed mapping\nsoftware that allows you to download map .... Microsoft released the final version of the Microsoft .NET Framework 4.8 on\nApril 18, 2019; links to offline installer and web installer are .... Ultimate Maps Downloader is a detailed mapping software that\nallows you to download map imagery, topographic and road maps from various .... Ultimate Maps Downloader 4.8.1 | 56.1\nMbUltimate Maps Downloader is a detailed mapping software that allows you to download map .... Tải phiên bản 4.8.1 phần mềm\nUltimate Maps Downloader - Tải về bản đồ vệ tinh.. Togetherwithsocialscienceclass10pdfdownload DOWNLOAD\nTogetherwithsocialscienceclass10pdfdownload . ... Sonic Dash 4.8.1 Apk Mod Money,Unlocked,Rings for android ... Ultimate\nMaps Downloader Crack Keygen.zip.. Universal Maps Downloader Keygen : is a powerful application that helps you get small\ntile images from Google Maps, Bing Maps, OpenStreet .... µTorrent is the official BitTorrent android torrent downloader. Enjoy\nawesome torrent downloading experience with no download speed or size .... Ultimate Maps\nDownloader破解版是一款简单好用的世界地图下载软件，使用可帮助用户快速从各种地图服务器上下载你需要的地图图像、地形图 .... Ultimate Maps Downloader is a\ndetailed mapping software that allows you to download both satellite imagery, topographic and road maps from Google Maps, ....\nRoot Explorer is the ultimate file manager for root users. Access the whole of android's file system (including the elusive data\nfolder!). Characteristics include .... Ultimate Maps Downloader 4.8.1\n一款非常專業的世界地圖下載軟件UltimateMapsDownloader是一款非常專業的世界地圖下載軟件，有了這款軟件，我們就可以 .... Ultimate Maps Downloader est\nun gestionnaire de téléchargements spécialisé dans le transfert des cartes ou des images par satellite sur la Toile. Il est facile à ....\nUltimate Maps Downloader. 4.8.1. Ultimate Maps Downloader. Download map imagery, topographic and road maps from\nvarious map servers. Wallpaper .... Ultimate Maps Downloader - Télécharger la dernière version, sans SMS | Obtenez les\ndernières versions de vos programmes.. This tool detects and tries to fix some frequently occurring issues with the setup of\nMicrosoft .NET Framework or with updates to the Microsoft .. Ultimate Maps Downloader. 4.8.1. 53 MO. موثوق خرائط تطبيق هو\n.portable 4.8.1 Downloader Maps Ultimate ..يساعدك على تنزيل صور الخرائط والخرائط الطبوغرافية وخرائط الطرق من. خوادم الخرائط المختلفة\nРазмер: 53.62 MB Сборки сделаны на VMware ThinApp Enterprise 5.2.5-12316299.. Universal Maps Downloader افزار نرم\n\n                               3 / 4\n\n\n\n \n\nMaps Ultimate Buy ..Maps Microsoft یا Maps Yahoo ,Maps Google ذخیره نقشه های ماهواره ای جهت دانلود نقشه های کوچک را از\nDownloader 4 genuine\u2063 license, Key Features, Overview, FAQ, Coupon Code.. Ultimate Maps Downloader. 4.8.1. By Lizard\nLabs. Ultimate Maps Downloader is a detailed mapping software that allows you to download map .... Download Dev-C++ for\nfree. A free, portable ... Map, analyze, and automate processes, manage regulatory compliance, assess risks within a single\nplatform!. Ultimate Maps Downloader 4.8.1. March 9 2020 0. ultimate maps, ultimate maps downloader, ultimate maps\ndownloader 3.0.1, ultimate maps downloader crack, .... MARVEL's Captain Marvel Update! 1. Captain Marvel Character\nUpdate - New Characters: Nick Fury, Minn-Erva, Korath - New Uniforms: Captain Marvel, Ronan .... Ultimate Maps\nDownloader 4.8.1 | 56.1 Mb Ultimate Maps Downloader is a detailed mapping software that allows you to download map\nimagery, topographic .... Ultimate Maps Downloader 5.9.13 Torrent Download 2019. This product is always a good utility to\nturn ... Version, 4.8.1. Updated, 08/06/2019 .... Download Ultimate Maps Downloader 4.8.1 Crack Phần mềm lập bản đồ chi\ntiết cho phép bạn tải xuống hình ảnh bản đồ, bản đồ địa hình và .... 22 Jun 2014 Download MTV India Coke Studio Season 3\ntorrent or any other to ... 28 Aug 2012 ... Ultimate Maps Downloader 4.8.1 With Crack. ultimate maps downloader, ultimate\nmaps, ultimate maps downloader 4.8.1 crack, ultimate maps wordpress, ultimate maps downloader full version, ultimate .... How\nto uninstall Ultimate Maps Downloader Version 4.8.1 by UMD? Learn how to remove Ultimate Maps Downloader Version\n4.8.1 from your computer. d299cc6e31 \n\nHD Online Player (Dilwale Dulhania Le Jayenge movie fu)\nfish tycoon apk full version\nMark Studio 2 Crack 3instmank\nintelliscore ensemble full crack 43\nliteratura brasileira william cereja e thereza cochar pdf 13\nOthello Story In Tamil Pdf Download\nKey To The Treasures Of Jannah Book Pdf\nThe Immortals Of Meluha Ebook Epub Torrents\nVehicle Fleet Manager 4.0 Serial Key\nmu hobby dl wings legendary set.ZIP\n\nUltimate Maps Downloader 481\n\n                               4 / 4\n\nhttps://documen.site/download/hd-online-player-dilwale-dulhania-le-jayenge-movie-fu_pdf\nhttps://trello.com/c/1pJAV1Ba/365-top-fish-tycoon-apk-full-version\nhttps://trello.com/c/LsthbulW/363-mark-studio-2-crack-3instmank-2020\nhttps://uploads.strikinglycdn.com/files/e4f0513d-e90d-41a4-8e3b-ccce31cc28d8/intelliscore-ensemble-full-crack-43.pdf\nhttp://nacyclavi.tistory.com/79\nhttp://pukusaesu.tistory.com/47\nhttps://documen.site/download/key-to-the-treasures-of-jannah-book-pdf_pdf\nhttps://documen.site/download/the-immortals-of-meluha-ebook-epub-torrents_pdf\nhttps://trello.com/c/nlKi4dkd/368-vehicle-fleet-manager-40-serial-key-best\nhttps://trello.com/c/ItsXoic1/154-exclusive-mu-hobby-dl-wings-legendary-setzip\nhttp://www.tcpdf.org\n\n",
    "metadata": {
        "pdf:PDFVersion": "1.7",
        "xmp:CreatorTool": "derolaqu",
        "pdf:docinfo:title": "Ultimate Maps Downloader 481",
        "pdf:hasXFA": "false",
        "X-TIKA:Parsed-By-Full-Set": ["org.apache.tika.parser.DefaultParser", "org.apache.tika.parser.pdf.PDFParser"],
        "pdf:num3DAnnotations": "0",
        "dc:format": "application/pdf; version=1.7",
        "pdf:docinfo:creator_tool": "derolaqu",
        "access_permission:fill_in_form": "true",
        "pdf:hasCollection": "false",
        "pdf:encrypted": "false",
        "dc:title": "Ultimate Maps Downloader 481",
        "pdf:containsNonEmbeddedFont": "true",
        "xmp:CreateDate": "2021-06-27T17:39:21Z",
        "pdf:hasMarkedContent": "false",
        "pdf:ocrPageCount": "0",
        "access_permission:can_print_faithful": "true",
        "xmp:ModifyDate": "2021-06-27T17:39:21Z",
        "pdf:docinfo:creator": "derolaqu",
        "access_permission:extract_for_accessibility": "true",
        "resourceName": "b'tmpteif6nx9'",
        "X-TIKA:Parsed-By": ["org.apache.tika.parser.DefaultParser", "org.apache.tika.parser.pdf.PDFParser"],
        "pdf:annotationTypes": [
            "0001-0000",
            "0001-0001",
            "0004-0000",
            "0004-0001",
            "0004-0002",
            "0004-0003",
            "0004-0004",
            "0004-0005",
            "0004-0006",
            "0004-0007",
            "0004-0008",
            "0004-0009",
            "0004-0010",
        ],
        "pdf:docinfo:producer": "PDF Master 1.0.1",
        "pdf:annotationSubtypes": "Link",
        "pdf:containsDamagedFont": "false",
        "pdf:unmappedUnicodeCharsPerPage": ["0", "0", "0", "0"],
        "access_permission:modify_annotations": "true",
        "dc:creator": "derolaqu",
        "dcterms:created": "2021-06-27T17:39:21Z",
        "dcterms:modified": "2021-06-27T17:39:21Z",
        "xmpMM:DocumentID": "uuid:25052966-d025-ed9f-8abe-e42a614362d8",
        "pdf:overallPercentageUnmappedUnicodeChars": "0.0",
        "pdf:docinfo:keywords": "derolaqu",
        "pdf:docinfo:modified": "2021-06-27T17:39:21Z",
        "Content-Length": "166804",
        "Content-Type": "application/pdf",
        "xmp:MetadataDate": "2021-06-27T17:39:21Z",
        "pdf:producer": "PDF Master 1.0.1",
        "dc:subject": "derolaqu",
        "pdf:totalUnmappedUnicodeChars": "0",
        "access_permission:assemble_document": "true",
        "xmpTPg:NPages": "4",
        "pdf:hasXMP": "true",
        "pdf:charsPerPage": ["37", "4553", "5912", "2142"],
        "access_permission:extract_content": "true",
        "access_permission:can_print": "true",
        "pdf:docinfo:trapped": "False",
        "meta:keyword": "derolaqu",
        "access_permission:can_modify": "true",
        "pdf:docinfo:created": "2021-06-27T17:39:21Z",
    },
    "attachments": {},
}

TEST_ENCRYPTED_ZIP_DATA = {
    "content": "993846fa2d67316f884aa7bc9d0cd7922abab515458a3ce2caa857d77bca0267.exe\n",
    "metadata": {
        "X-TIKA:EXCEPTION:embedded_stream_exception": "org.apache.tika.exception.EncryptedDocumentException: stream (993846fa2d67316f884aa7bc9d0cd7922abab515458a3ce2caa857d77bca0267.exe) is encrypted\n\tat org.apache.tika.parser.pkg.PackageParser.parseEntry(PackageParser.java:492)\n\tat org.apache.tika.parser.pkg.PackageParser.parseEntries(PackageParser.java:386)\n\tat org.apache.tika.parser.pkg.PackageParser._parse(PackageParser.java:336)\n\tat org.apache.tika.parser.pkg.PackageParser.parse(PackageParser.java:259)\n\tat org.apache.tika.parser.CompositeParser.parse(CompositeParser.java:298)\n\tat org.apache.tika.parser.CompositeParser.parse(CompositeParser.java:298)\n\tat org.apache.tika.parser.AutoDetectParser.parse(AutoDetectParser.java:204)\n\tat org.apache.tika.server.core.resource.TikaResource.parse(TikaResource.java:363)\n\tat org.apache.tika.server.core.resource.UnpackerResource.process(UnpackerResource.java:152)\n\tat org.apache.tika.server.core.resource.UnpackerResource.unpackAll(UnpackerResource.java:106)\n\tat java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)\n\tat java.base/java.lang.reflect.Method.invoke(Method.java:580)\n\tat org.apache.cxf.service.invoker.AbstractInvoker.performInvocation(AbstractInvoker.java:179)\n\tat org.apache.cxf.service.invoker.AbstractInvoker.invoke(AbstractInvoker.java:96)\n\tat org.apache.cxf.jaxrs.JAXRSInvoker.invoke(JAXRSInvoker.java:200)\n\tat org.apache.cxf.jaxrs.JAXRSInvoker.invoke(JAXRSInvoker.java:103)\n\tat org.apache.cxf.interceptor.ServiceInvokerInterceptor$1.run(ServiceInvokerInterceptor.java:59)\n\tat org.apache.cxf.interceptor.ServiceInvokerInterceptor.handleMessage(ServiceInvokerInterceptor.java:96)\n\tat org.apache.cxf.phase.PhaseInterceptorChain.doIntercept(PhaseInterceptorChain.java:307)\n\tat org.apache.cxf.transport.ChainInitiationObserver.onMessage(ChainInitiationObserver.java:121)\n\tat org.apache.cxf.transport.http.AbstractHTTPDestination.invoke(AbstractHTTPDestination.java:265)\n\tat org.apache.cxf.transport.http_jetty.JettyHTTPDestination.doService(JettyHTTPDestination.java:244)\n\tat org.apache.cxf.transport.http_jetty.JettyHTTPHandler.handle(JettyHTTPHandler.java:80)\n\tat org.eclipse.jetty.server.handler.HandlerWrapper.handle(HandlerWrapper.java:122)\n\tat org.eclipse.jetty.server.handler.ScopedHandler.nextHandle(ScopedHandler.java:223)\n\tat org.eclipse.jetty.server.handler.ContextHandler.doHandle(ContextHandler.java:1381)\n\tat org.eclipse.jetty.server.handler.ScopedHandler.nextScope(ScopedHandler.java:178)\n\tat org.eclipse.jetty.server.handler.ContextHandler.doScope(ContextHandler.java:1303)\n\tat org.eclipse.jetty.server.handler.ScopedHandler.handle(ScopedHandler.java:129)\n\tat org.eclipse.jetty.server.handler.ContextHandlerCollection.handle(ContextHandlerCollection.java:149)\n\tat org.eclipse.jetty.server.handler.HandlerWrapper.handle(HandlerWrapper.java:122)\n\tat org.eclipse.jetty.server.Server.handle(Server.java:563)\n\tat org.eclipse.jetty.server.HttpChannel$RequestDispatchable.dispatch(HttpChannel.java:1598)\n\tat org.eclipse.jetty.server.HttpChannel.dispatch(HttpChannel.java:753)\n\tat org.eclipse.jetty.server.HttpChannel.handle(HttpChannel.java:501)\n\tat org.eclipse.jetty.server.HttpConnection.onFillable(HttpConnection.java:287)\n\tat org.eclipse.jetty.io.AbstractConnection$ReadCallback.succeeded(AbstractConnection.java:314)\n\tat org.eclipse.jetty.io.FillInterest.fillable(FillInterest.java:100)\n\tat org.eclipse.jetty.io.SelectableChannelEndPoint$1.run(SelectableChannelEndPoint.java:53)\n\tat org.eclipse.jetty.util.thread.strategy.AdaptiveExecutionStrategy.runTask(AdaptiveExecutionStrategy.java:421)\n\tat org.eclipse.jetty.util.thread.strategy.AdaptiveExecutionStrategy.consumeTask(AdaptiveExecutionStrategy.java:390)\n\tat org.eclipse.jetty.util.thread.strategy.AdaptiveExecutionStrategy.tryProduce(AdaptiveExecutionStrategy.java:277)\n\tat org.eclipse.jetty.util.thread.strategy.AdaptiveExecutionStrategy.run(AdaptiveExecutionStrategy.java:199)\n\tat org.eclipse.jetty.util.thread.ReservedThreadExecutor$ReservedThread.run(ReservedThreadExecutor.java:411)\n\tat org.eclipse.jetty.util.thread.QueuedThreadPool.runJob(QueuedThreadPool.java:969)\n\tat org.eclipse.jetty.util.thread.QueuedThreadPool$Runner.doRunJob(QueuedThreadPool.java:1194)\n\tat org.eclipse.jetty.util.thread.QueuedThreadPool$Runner.run(QueuedThreadPool.java:1149)\n\tat java.base/java.lang.Thread.run(Thread.java:1583)\n",
        "X-TIKA:Parsed-By": ["org.apache.tika.parser.DefaultParser", "org.apache.tika.parser.pkg.PackageParser"],
        "X-TIKA:Parsed-By-Full-Set": [
            "org.apache.tika.parser.DefaultParser",
            "org.apache.tika.parser.pkg.PackageParser",
        ],
        "resourceName": "b'tmpo3yeitc9'",
        "X-TIKA:detectedEncoding": "ISO-8859-1",
        "Content-Length": "699109",
        "X-TIKA:encodingDetector": "UniversalEncodingDetector",
        "Content-Type": "application/zip",
    },
    "attachments": {},
}

TEST_PNG_RESPONSE_DATA = {
    "content": "\n\n",
    "metadata": {
        "ICC:Profile Connection Space": "XYZ",
        "ICC:Luminance": "(76.0365, 80, 87.1246)",
        "Compression Type": "Baseline",
        "X-TIKA:Parsed-By-Full-Set": [
            "org.apache.tika.parser.DefaultParser",
            "org.apache.tika.parser.image.JpegParser",
            "org.apache.tika.parser.ocr.TesseractOCRParser",
        ],
        "ICC:Green Colorant": "(0.3851, 0.7169, 0.0971)",
        "Number of Components": "3",
        "Component 2": "Cb component: Quantization table 1, Sampling factors 1 horiz/1 vert",
        "Component 1": "Y component: Quantization table 0, Sampling factors 1 horiz/1 vert",
        "Exif IFD0:X Resolution": "72 dots per inch",
        "tiff:ResolutionUnit": "Inch",
        "Layers Group Information": "0 0 0 0",
        "ICC:Signature": "acsp",
        "ICC:Green TRC": "0.0, 0.0000763, 0.0001526, 0.0002289, 0.0003052, 0.0003815, 0.0004578, 0.0005341, 0.0006104, 0.0006867, 0.000763, 0.0008392, 0.0009003, 0.0009766, 0.0010529, 0.0011292, 0.0012055, 0.0012818, 0.0013581, 0.0014343, 0.0015106, 0.0015869, 0.0016632, 0.0017395, 0.0018158, 0.0018921, 0.0019684, 0.0020447, 0.002121, 0.0021973, 0.0022736, 0.0023499, 0.0024262, 0.0025025, 0.0025788, 0.0026551, 0.0027161, 0.0027924, 0.0028687, 0.002945, 0.0030213, 0.0030976, 0.0031739, 0.0032502, 0.0033417, 0.003418, 0.0034943, 0.0035859, 0.0036622, 0.0037537, 0.00383, 0.0039216, 0.0040131, 0.0041047, 0.0041962, 0.0042878, 0.0043793, 0.0044709, 0.0045624, 0.0046693, 0.0047608, 0.0048524, 0.0049592, 0.005066, 0.0051575, 0.0052644, 0.0053712, 0.005478, 0.0055848, 0.0056916, 0.0057984, 0.0059052, 0.0060273, 0.0061341, 0.0062562, 0.006363, 0.0064851, 0.0066072, 0.0067292, 0.0068513, 0.0069734, 0.0070954, 0.0072175, 0.0073396, 0.0074617, 0.007599, 0.0077211, 0.0078584, 0.0079957, 0.0081178, 0.0082551, 0.0083925, 0.0085298, 0.0086671, 0.0088045, 0.008957, 0.0090944, 0.0092317, 0.0093843, 0.0095369, 0.0096742, 0.0098268, 0.0099794, 0.010132, 0.0102846, 0.0104372, 0.0105898, 0.0107576, 0.0109102, 0.0110628, 0.0112306, 0.0113985, 0.0115511, 0.0117189, 0.0118868, 0.0120546, 0.0122225, 0.0124056, 0.0125734, 0.0127413, 0.0129244, 0.0130922, 0.0132753, 0.0134585, 0.0136416, 0.0138247, 0.0140078, 0.0141909, 0.014374, 0.0145571, 0.0147555, 0.0149386, 0.0151369, 0.0153201, 0.0155184, 0.0157168, 0.0159152, 0.0161135, 0.0163119, 0.0165255, 0.0167239, 0.0169223, 0.0171359, 0.0173495, 0.0175479, 0.0177615, 0.0179751, 0.0181888, 0.0184024, 0.018616, 0.0188449, 0.0190585, 0.0192874, 0.019501, 0.0197299, 0.0199588, 0.0201877, 0.0204166, 0.0206455, 0.0208743, 0.0211032, 0.0213474, 0.0215763, 0.0218204, 0.0220645, 0.0222934, 0.0225376, 0.0227817, 0.0230259, 0.0232853, 0.0235294, 0.0237736, 0.024033, 0.0242771, 0.0245365, 0.0247959, 0.0250553, 0.0253147, 0.0255741, 0.0258335, 0.0261082, 0.0263676, 0.026627, 0.0269017, 0.0271763, 0.027451, 0.0277256, 0.0280003, 0.028275, 0.0285496, 0.0288243, 0.0291142, 0.0293889, 0.0296788, 0.0299687, 0.0302586, 0.0305486, 0.0308385, 0.0311284, 0.0314183, 0.0317235, 0.0320134, 0.0323186, 0.0326238, 0.032929, 0.0332341, 0.0335393, 0.0338445, 0.0341497, 0.0344549, 0.0347753, 0.0350805, 0.0354009, 0.0357214, 0.0360418, 0.0363622, 0.0366827, 0.0370031, 0.0373388, 0.0376593, 0.037995, 0.0383154, 0.0386511, 0.0389868, 0.0393225, 0.0396582, 0.0399939, 0.0403449, 0.0406806, 0.0410315, 0.0413825, 0.0417182, 0.0420691, 0.0424201, 0.042771, 0.0431373, 0.0434882, 0.0438392, 0.0442054, 0.0445716, 0.0449226, 0.0452888, 0.045655, 0.0460212, 0.0464027, 0.0467689, 0.0471504, 0.0475166, 0.0478981, 0.0482795, 0.048661, 0.0490425, 0.049424, 0.0498054, 0.0501869, 0.0505837, 0.0509804, 0.0513619, 0.0517586, 0.0521553, 0.0525521, 0.0529488, 0.0533608, 0.0537575, 0.0541695, 0.0545663, 0.0549783, 0.0553902, 0.0558022, 0.0562142, 0.0566262, 0.0570535, 0.0574655, 0.0578927, 0.05832, 0.058732, 0.0591592, 0.0595865, 0.060029, 0.0604562, 0.0608835, 0.061326, 0.0617533, 0.0621958, 0.0626383, 0.0630808, 0.0635233, 0.0639811, 0.0644236, 0.0648661, 0.0653239, 0.0657816, 0.0662394, 0.0666972, 0.067155, 0.0676127, 0.0680705, 0.0685435, 0.0690013, 0.0694743, 0.0699474, 0.0704204, 0.0708934, 0.0713664, 0.0718395, 0.0723278, 0.0728008, 0.0732891, 0.0737774, 0.0742657, 0.0747539, 0.0752422, 0.0757305, 0.0762188, 0.0767224, 0.0772259, 0.0777142, 0.0782177, 0.0787213, 0.0792401, 0.0797436, 0.0802472, 0.080766, 0.0812696, 0.0817884, 0.0823072, 0.082826, 0.0833448, 0.0838636, 0.0843977, 0.0849165, 0.0854505, 0.0859846, 0.0865187, 0.0870527, 0.0875868, 0.0881209, 0.0886549, 0.0892042, 0.0897536, 0.0902876, 0.090837, 0.0913863, 0.0919356, 0.0925002, 0.0930495, 0.0936141, 0.0941634, 0.094728, 0.0952926, 0.0958572, 0.0964218, 0.0970016, 0.0975662, 0.098146, 0.0987106, 0.0992905, 0.0998703, 0.1004501, 0.10103, 0.1016251, 0.1022049, 0.1028, 0.1033799, 0.103975, 0.1045701, 0.1051652, 0.1057755, 0.1063706, 0.106981, 0.1075761, 0.1081865, 0.1087968, 0.1094072, 0.1100175, 0.1106279, 0.1112535, 0.1118639, 0.1124895, 0.1131151, 0.1137407, 0.1143664, 0.114992, 0.1156176, 0.1162585, 0.1168841, 0.117525, 0.1181659, 0.1188067, 0.1194476, 0.1200885, 0.1207446, 0.1213855, 0.1220417, 0.1226978, 0.1233539, 0.1240101, 0.1246662, 0.1253223, 0.1259937, 0.1266499, 0.1273213, 0.1279927, 0.1286641, 0.1293355, 0.1300069, 0.1306935, 0.1313649, 0.1320516, 0.1327382, 0.1334096, 0.1341115, 0.1347982, 0.1354849, 0.1361868, 0.1368734, 0.1375753, 0.1382773, 0.1389792, 0.1396811, 0.140383, 0.1411002, 0.1418021, 0.1425193, 0.1432364, 0.1439536, 0.1446708, 0.145388, 0.1461204, 0.1468376, 0.14757, 0.1483024, 0.1490349, 0.1497673, 0.1504997, 0.1512322, 0.1519799, 0.1527123, 0.15346, 0.1542077, 0.1549554, 0.1557031, 0.1564508, 0.1572137, 0.1579767, 0.1587243, 0.1594873, 0.1602502, 0.1610132, 0.1617914, 0.1625544, 0.1633326, 0.1640955, 0.1648737, 0.1656519, 0.1664302, 0.1672236, 0.1680018, 0.1687953, 0.1695735, 0.170367, 0.1711604, 0.1719539, 0.1727474, 0.1735561, 0.1743496, 0.1751583, 0.175967, 0.1767758, 0.1775845, 0.1783932, 0.1792172, 0.1800259, 0.1808499, 0.1816739, 0.1824826, 0.1833219, 0.1841459, 0.1849699, 0.1858091, 0.1866331, 0.1874723, 0.1883116, 0.1891508, 0.1900053, 0.1908446, 0.1916838, 0.1925383, 0.1933928, 0.1942473, 0.1951019, 0.1959564, 0.1968261, 0.1976806, 0.1985504, 0.1994202, 0.2002899, 0.2011597, 0.2020294, 0.2028992, 0.2037842, 0.2046693, 0.205539, 0.206424, 0.2073243, 0.2082094, 0.2090944, 0.2099947, 0.2108949, 0.21178, 0.2126802, 0.2135958, 0.2144961, 0.2153964, 0.2163119, 0.2172274, 0.2181277, 0.2190585, 0.2199741, 0.2208896, 0.2218051, 0.2227359, 0.2236667, 0.2245975, 0.2255283, 0.2264591, 0.2273899, 0.228336, 0.2292821, 0.2302129, 0.2311589, 0.232105, 0.2330663, 0.2340124, 0.2349737, 0.2359197, 0.2368811, 0.2378424, 0.2388037, 0.239765, 0.2407416, 0.2417029, 0.2426795, 0.2436561, 0.2446326, 0.2456092, 0.2466011, 0.2475776, 0.2485695, 0.249546, 0.2505379, 0.2515297, 0.2525368, 0.2535286, 0.2545357, 0.2555276, 0.2565347, 0.2575418, 0.2585489, 0.259556, 0.2605783, 0.2615854, 0.2626078, 0.2636301, 0.2646525, 0.2656748, 0.2667124, 0.2677348, 0.2687724, 0.26981, 0.2708324, 0.2718853, 0.2729229, 0.2739605, 0.2750134, 0.276051, 0.2771038, 0.2781567, 0.2792248, 0.2802777, 0.2813306, 0.2823987, 0.2834668, 0.284535, 0.2856031, 0.2866712, 0.2877394, 0.2888228, 0.2899062, 0.2909743, 0.2920577, 0.2931563, 0.2942397, 0.2953231, 0.2964218, 0.2975204, 0.2986191, 0.2997177, 0.3008164, 0.301915, 0.3030289, 0.3041428, 0.3052567, 0.3063706, 0.3074846, 0.3085985, 0.3097124, 0.3108415, 0.3119707, 0.3130999, 0.314229, 0.3153582, 0.3165026, 0.3176318, 0.3187762, 0.3199207, 0.3210651, 0.3222095, 0.3233539, 0.3245136, 0.3256733, 0.3268177, 0.3279774, 0.3291371, 0.330312, 0.3314717, 0.3326467, 0.3338216, 0.3349966, 0.3361715, 0.3373465, 0.3385214, 0.3397116, 0.3408865, 0.3420768, 0.343267, 0.3444724, 0.3456626, 0.3468528, 0.3480583, 0.3492638, 0.3504692, 0.3516747, 0.3528801, 0.3541009, 0.3553063, 0.356527, 0.3577478, 0.3589685, 0.3601892, 0.3614252, 0.3626459, 0.3638819, 0.3651179, 0.3663539, 0.3675898, 0.3688411, 0.3700771, 0.3713283, 0.3725795, 0.3738308, 0.375082, 0.3763333, 0.3775998, 0.378851, 0.3801175, 0.381384, 0.3826505, 0.3839322, 0.3851987, 0.3864805, 0.387747, 0.3890288, 0.3903105, 0.3916075, 0.3928893, 0.3941863, 0.3954681, 0.3967651, 0.3980621, 0.3993744, 0.4006714, 0.4019837, 0.4032807, 0.404593, 0.4059052, 0.4072175, 0.4085451, 0.4098573, 0.4111849, 0.4125124, 0.4138399, 0.4151675, 0.416495, 0.4178378, 0.4191806, 0.4205234, 0.4218662, 0.423209, 0.4245518, 0.4259098, 0.4272526, 0.4286107, 0.4299687, 0.4313268, 0.4326848, 0.4340581, 0.4354314, 0.4367895, 0.4381628, 0.4395514, 0.4409247, 0.442298, 0.4436866, 0.4450752, 0.4464637, 0.4478523, 0.4492409, 0.4506447, 0.4520333, 0.4534371, 0.4548409, 0.4562448, 0.4576486, 0.4590677, 0.4604715, 0.4618906, 0.4633097, 0.4647288, 0.4661631, 0.4675822, 0.4690166, 0.4704356, 0.47187, 0.4733043, 0.4747539, 0.4761883, 0.4776379, 0.4790875, 0.4805371, 0.4819867, 0.4834363, 0.4848859, 0.4863508, 0.4878157, 0.4892805, 0.4907454, 0.4922103, 0.4936904, 0.4951553, 0.4966354, 0.4981155, 0.4995956, 0.501091, 0.5025711, 0.5040665, 0.5055467, 0.507042, 0.5085527, 0.5100481, 0.5115435, 0.5130541, 0.5145647, 0.5160754, 0.517586, 0.5190967, 0.5206226, 0.5221485, 0.5236591, 0.525185, 0.5267262, 0.5282521, 0.529778, 0.5313191, 0.5328603, 0.5344015, 0.5359426, 0.537499, 0.5390402, 0.5405966, 0.542153, 0.5437095, 0.5452659, 0.5468223, 0.548394, 0.5499657, 0.5515373, 0.553109, 0.5546807, 0.5562524, 0.5578393, 0.5594263, 0.5610132, 0.5626001, 0.5641871, 0.565774, 0.5673762, 0.5689784, 0.5705806, 0.5721828, 0.573785, 0.5754025, 0.5770047, 0.5786221, 0.5802396, 0.581857, 0.5834897, 0.5851072, 0.5867399, 0.5883726, 0.5900053, 0.5916381, 0.5932708, 0.5949187, 0.5965667, 0.5982147, 0.5998627, 0.6015106, 0.6031586, 0.6048219, 0.6064851, 0.6081483, 0.6098116, 0.6114748, 0.6131533, 0.6148165, 0.616495, 0.6181735, 0.619852, 0.6215457, 0.6232242, 0.624918, 0.6266117, 0.6283055, 0.6299992, 0.631693, 0.633402, 0.635111, 0.63682, 0.638529, 0.640238, 0.6419471, 0.6436713, 0.6453956, 0.6471199, 0.6488441, 0.6505684, 0.6523079, 0.6540322, 0.6557717, 0.6575113, 0.6592508, 0.6610056, 0.6627451, 0.6644999, 0.6662547, 0.6680095, 0.6697642, 0.6715343, 0.6732891, 0.6750591, 0.6768292, 0.6785992, 0.6803845, 0.6821546, 0.6839399, 0.6857252, 0.6875105, 0.6892958, 0.6910811, 0.6928817, 0.6946822, 0.6964675, 0.6982834, 0.7000839, 0.7018845, 0.7037003, 0.7055161, 0.707332, 0.7091478, 0.7109636, 0.7127947, 0.7146105, 0.7164416, 0.7182727, 0.720119, 0.7219501, 0.7237964, 0.7256275, 0.7274739, 0.7293355, 0.7311818, 0.7330282, 0.7348898, 0.7367514, 0.738613, 0.7404746, 0.7423514, 0.744213, 0.7460899, 0.7479667, 0.7498436, 0.7517205, 0.7536126, 0.7554894, 0.7573816, 0.7592737, 0.7611658, 0.7630732, 0.7649653, 0.7668727, 0.76878, 0.7706874, 0.7725948, 0.7745174, 0.7764248, 0.7783474, 0.7802701, 0.7821927, 0.7841306, 0.7860533, 0.7879911, 0.789929, 0.7918669, 0.7938048, 0.795758, 0.7976959, 0.799649, 0.8016022, 0.8035554, 0.8055238, 0.8074769, 0.8094453, 0.8114137, 0.8133822, 0.8153506, 0.8173342, 0.8193179, 0.8212863, 0.82327, 0.8252689, 0.8272526, 0.8292515, 0.8312352, 0.8332341, 0.8352331, 0.8372473, 0.8392462, 0.8412604, 0.8432746, 0.8452888, 0.847303, 0.8493172, 0.8513466, 0.8533761, 0.8554055, 0.857435, 0.8594644, 0.8614939, 0.8635386, 0.8655833, 0.867628, 0.8696727, 0.8717327, 0.8737774, 0.8758373, 0.8778973, 0.8799573, 0.8820325, 0.8840925, 0.8861677, 0.8882429, 0.8903182, 0.8923934, 0.8944839, 0.8965591, 0.8986496, 0.9007401, 0.9028305, 0.9049363, 0.9070268, 0.9091325, 0.9112383, 0.913344, 0.915465, 0.9175708, 0.9196918, 0.9218128, 0.9239338, 0.9260548, 0.9281758, 0.930312, 0.9324483, 0.9345846, 0.9367208, 0.9388571, 0.9410086, 0.9431601, 0.9453117, 0.9474632, 0.9496147, 0.9517815, 0.953933, 0.9560998, 0.9582666, 0.9604334, 0.9626154, 0.9647822, 0.9669642, 0.9691463, 0.9713283, 0.9735256, 0.9757076, 0.9779049, 0.9801022, 0.9822995, 0.9844968, 0.9867094, 0.988922, 0.9911345, 0.9933471, 0.9955596, 0.9977722, 1.0",
        "ICC:Media White Point": "(0.9505, 1, 1.0891)",
        "Version Info": "1 (Adobe Photoshop, Adobe Photoshop CS5.1) 1",
        "Component 3": "Cr component: Quantization table 1, Sampling factors 1 horiz/1 vert",
        "Exif Thumbnail:Thumbnail Offset": "308 bytes",
        "tiff:BitsPerSample": "8",
        "Caption Digest": "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        "Resolution Info": "72x72 DPI",
        "Exif Thumbnail:X Resolution": "72 dots per inch",
        "tiff:Orientation": "1",
        "ICC:Version": "2.1.0",
        "tiff:Software": "Adobe Photoshop CS5.1 Windows",
        "ICC:Profile Size": "3144",
        "ICC:Blue Colorant": "(0.1431, 0.0606, 0.7141)",
        "tiff:YResolution": "72.0",
        "ICC:Device Mfg Description": "IEC http://www.iec.ch",
        "Seed Number": "2",
        "ICC:Red TRC": "0.0, 0.0000763, 0.0001526, 0.0002289, 0.0003052, 0.0003815, 0.0004578, 0.0005341, 0.0006104, 0.0006867, 0.000763, 0.0008392, 0.0009003, 0.0009766, 0.0010529, 0.0011292, 0.0012055, 0.0012818, 0.0013581, 0.0014343, 0.0015106, 0.0015869, 0.0016632, 0.0017395, 0.0018158, 0.0018921, 0.0019684, 0.0020447, 0.002121, 0.0021973, 0.0022736, 0.0023499, 0.0024262, 0.0025025, 0.0025788, 0.0026551, 0.0027161, 0.0027924, 0.0028687, 0.002945, 0.0030213, 0.0030976, 0.0031739, 0.0032502, 0.0033417, 0.003418, 0.0034943, 0.0035859, 0.0036622, 0.0037537, 0.00383, 0.0039216, 0.0040131, 0.0041047, 0.0041962, 0.0042878, 0.0043793, 0.0044709, 0.0045624, 0.0046693, 0.0047608, 0.0048524, 0.0049592, 0.005066, 0.0051575, 0.0052644, 0.0053712, 0.005478, 0.0055848, 0.0056916, 0.0057984, 0.0059052, 0.0060273, 0.0061341, 0.0062562, 0.006363, 0.0064851, 0.0066072, 0.0067292, 0.0068513, 0.0069734, 0.0070954, 0.0072175, 0.0073396, 0.0074617, 0.007599, 0.0077211, 0.0078584, 0.0079957, 0.0081178, 0.0082551, 0.0083925, 0.0085298, 0.0086671, 0.0088045, 0.008957, 0.0090944, 0.0092317, 0.0093843, 0.0095369, 0.0096742, 0.0098268, 0.0099794, 0.010132, 0.0102846, 0.0104372, 0.0105898, 0.0107576, 0.0109102, 0.0110628, 0.0112306, 0.0113985, 0.0115511, 0.0117189, 0.0118868, 0.0120546, 0.0122225, 0.0124056, 0.0125734, 0.0127413, 0.0129244, 0.0130922, 0.0132753, 0.0134585, 0.0136416, 0.0138247, 0.0140078, 0.0141909, 0.014374, 0.0145571, 0.0147555, 0.0149386, 0.0151369, 0.0153201, 0.0155184, 0.0157168, 0.0159152, 0.0161135, 0.0163119, 0.0165255, 0.0167239, 0.0169223, 0.0171359, 0.0173495, 0.0175479, 0.0177615, 0.0179751, 0.0181888, 0.0184024, 0.018616, 0.0188449, 0.0190585, 0.0192874, 0.019501, 0.0197299, 0.0199588, 0.0201877, 0.0204166, 0.0206455, 0.0208743, 0.0211032, 0.0213474, 0.0215763, 0.0218204, 0.0220645, 0.0222934, 0.0225376, 0.0227817, 0.0230259, 0.0232853, 0.0235294, 0.0237736, 0.024033, 0.0242771, 0.0245365, 0.0247959, 0.0250553, 0.0253147, 0.0255741, 0.0258335, 0.0261082, 0.0263676, 0.026627, 0.0269017, 0.0271763, 0.027451, 0.0277256, 0.0280003, 0.028275, 0.0285496, 0.0288243, 0.0291142, 0.0293889, 0.0296788, 0.0299687, 0.0302586, 0.0305486, 0.0308385, 0.0311284, 0.0314183, 0.0317235, 0.0320134, 0.0323186, 0.0326238, 0.032929, 0.0332341, 0.0335393, 0.0338445, 0.0341497, 0.0344549, 0.0347753, 0.0350805, 0.0354009, 0.0357214, 0.0360418, 0.0363622, 0.0366827, 0.0370031, 0.0373388, 0.0376593, 0.037995, 0.0383154, 0.0386511, 0.0389868, 0.0393225, 0.0396582, 0.0399939, 0.0403449, 0.0406806, 0.0410315, 0.0413825, 0.0417182, 0.0420691, 0.0424201, 0.042771, 0.0431373, 0.0434882, 0.0438392, 0.0442054, 0.0445716, 0.0449226, 0.0452888, 0.045655, 0.0460212, 0.0464027, 0.0467689, 0.0471504, 0.0475166, 0.0478981, 0.0482795, 0.048661, 0.0490425, 0.049424, 0.0498054, 0.0501869, 0.0505837, 0.0509804, 0.0513619, 0.0517586, 0.0521553, 0.0525521, 0.0529488, 0.0533608, 0.0537575, 0.0541695, 0.0545663, 0.0549783, 0.0553902, 0.0558022, 0.0562142, 0.0566262, 0.0570535, 0.0574655, 0.0578927, 0.05832, 0.058732, 0.0591592, 0.0595865, 0.060029, 0.0604562, 0.0608835, 0.061326, 0.0617533, 0.0621958, 0.0626383, 0.0630808, 0.0635233, 0.0639811, 0.0644236, 0.0648661, 0.0653239, 0.0657816, 0.0662394, 0.0666972, 0.067155, 0.0676127, 0.0680705, 0.0685435, 0.0690013, 0.0694743, 0.0699474, 0.0704204, 0.0708934, 0.0713664, 0.0718395, 0.0723278, 0.0728008, 0.0732891, 0.0737774, 0.0742657, 0.0747539, 0.0752422, 0.0757305, 0.0762188, 0.0767224, 0.0772259, 0.0777142, 0.0782177, 0.0787213, 0.0792401, 0.0797436, 0.0802472, 0.080766, 0.0812696, 0.0817884, 0.0823072, 0.082826, 0.0833448, 0.0838636, 0.0843977, 0.0849165, 0.0854505, 0.0859846, 0.0865187, 0.0870527, 0.0875868, 0.0881209, 0.0886549, 0.0892042, 0.0897536, 0.0902876, 0.090837, 0.0913863, 0.0919356, 0.0925002, 0.0930495, 0.0936141, 0.0941634, 0.094728, 0.0952926, 0.0958572, 0.0964218, 0.0970016, 0.0975662, 0.098146, 0.0987106, 0.0992905, 0.0998703, 0.1004501, 0.10103, 0.1016251, 0.1022049, 0.1028, 0.1033799, 0.103975, 0.1045701, 0.1051652, 0.1057755, 0.1063706, 0.106981, 0.1075761, 0.1081865, 0.1087968, 0.1094072, 0.1100175, 0.1106279, 0.1112535, 0.1118639, 0.1124895, 0.1131151, 0.1137407, 0.1143664, 0.114992, 0.1156176, 0.1162585, 0.1168841, 0.117525, 0.1181659, 0.1188067, 0.1194476, 0.1200885, 0.1207446, 0.1213855, 0.1220417, 0.1226978, 0.1233539, 0.1240101, 0.1246662, 0.1253223, 0.1259937, 0.1266499, 0.1273213, 0.1279927, 0.1286641, 0.1293355, 0.1300069, 0.1306935, 0.1313649, 0.1320516, 0.1327382, 0.1334096, 0.1341115, 0.1347982, 0.1354849, 0.1361868, 0.1368734, 0.1375753, 0.1382773, 0.1389792, 0.1396811, 0.140383, 0.1411002, 0.1418021, 0.1425193, 0.1432364, 0.1439536, 0.1446708, 0.145388, 0.1461204, 0.1468376, 0.14757, 0.1483024, 0.1490349, 0.1497673, 0.1504997, 0.1512322, 0.1519799, 0.1527123, 0.15346, 0.1542077, 0.1549554, 0.1557031, 0.1564508, 0.1572137, 0.1579767, 0.1587243, 0.1594873, 0.1602502, 0.1610132, 0.1617914, 0.1625544, 0.1633326, 0.1640955, 0.1648737, 0.1656519, 0.1664302, 0.1672236, 0.1680018, 0.1687953, 0.1695735, 0.170367, 0.1711604, 0.1719539, 0.1727474, 0.1735561, 0.1743496, 0.1751583, 0.175967, 0.1767758, 0.1775845, 0.1783932, 0.1792172, 0.1800259, 0.1808499, 0.1816739, 0.1824826, 0.1833219, 0.1841459, 0.1849699, 0.1858091, 0.1866331, 0.1874723, 0.1883116, 0.1891508, 0.1900053, 0.1908446, 0.1916838, 0.1925383, 0.1933928, 0.1942473, 0.1951019, 0.1959564, 0.1968261, 0.1976806, 0.1985504, 0.1994202, 0.2002899, 0.2011597, 0.2020294, 0.2028992, 0.2037842, 0.2046693, 0.205539, 0.206424, 0.2073243, 0.2082094, 0.2090944, 0.2099947, 0.2108949, 0.21178, 0.2126802, 0.2135958, 0.2144961, 0.2153964, 0.2163119, 0.2172274, 0.2181277, 0.2190585, 0.2199741, 0.2208896, 0.2218051, 0.2227359, 0.2236667, 0.2245975, 0.2255283, 0.2264591, 0.2273899, 0.228336, 0.2292821, 0.2302129, 0.2311589, 0.232105, 0.2330663, 0.2340124, 0.2349737, 0.2359197, 0.2368811, 0.2378424, 0.2388037, 0.239765, 0.2407416, 0.2417029, 0.2426795, 0.2436561, 0.2446326, 0.2456092, 0.2466011, 0.2475776, 0.2485695, 0.249546, 0.2505379, 0.2515297, 0.2525368, 0.2535286, 0.2545357, 0.2555276, 0.2565347, 0.2575418, 0.2585489, 0.259556, 0.2605783, 0.2615854, 0.2626078, 0.2636301, 0.2646525, 0.2656748, 0.2667124, 0.2677348, 0.2687724, 0.26981, 0.2708324, 0.2718853, 0.2729229, 0.2739605, 0.2750134, 0.276051, 0.2771038, 0.2781567, 0.2792248, 0.2802777, 0.2813306, 0.2823987, 0.2834668, 0.284535, 0.2856031, 0.2866712, 0.2877394, 0.2888228, 0.2899062, 0.2909743, 0.2920577, 0.2931563, 0.2942397, 0.2953231, 0.2964218, 0.2975204, 0.2986191, 0.2997177, 0.3008164, 0.301915, 0.3030289, 0.3041428, 0.3052567, 0.3063706, 0.3074846, 0.3085985, 0.3097124, 0.3108415, 0.3119707, 0.3130999, 0.314229, 0.3153582, 0.3165026, 0.3176318, 0.3187762, 0.3199207, 0.3210651, 0.3222095, 0.3233539, 0.3245136, 0.3256733, 0.3268177, 0.3279774, 0.3291371, 0.330312, 0.3314717, 0.3326467, 0.3338216, 0.3349966, 0.3361715, 0.3373465, 0.3385214, 0.3397116, 0.3408865, 0.3420768, 0.343267, 0.3444724, 0.3456626, 0.3468528, 0.3480583, 0.3492638, 0.3504692, 0.3516747, 0.3528801, 0.3541009, 0.3553063, 0.356527, 0.3577478, 0.3589685, 0.3601892, 0.3614252, 0.3626459, 0.3638819, 0.3651179, 0.3663539, 0.3675898, 0.3688411, 0.3700771, 0.3713283, 0.3725795, 0.3738308, 0.375082, 0.3763333, 0.3775998, 0.378851, 0.3801175, 0.381384, 0.3826505, 0.3839322, 0.3851987, 0.3864805, 0.387747, 0.3890288, 0.3903105, 0.3916075, 0.3928893, 0.3941863, 0.3954681, 0.3967651, 0.3980621, 0.3993744, 0.4006714, 0.4019837, 0.4032807, 0.404593, 0.4059052, 0.4072175, 0.4085451, 0.4098573, 0.4111849, 0.4125124, 0.4138399, 0.4151675, 0.416495, 0.4178378, 0.4191806, 0.4205234, 0.4218662, 0.423209, 0.4245518, 0.4259098, 0.4272526, 0.4286107, 0.4299687, 0.4313268, 0.4326848, 0.4340581, 0.4354314, 0.4367895, 0.4381628, 0.4395514, 0.4409247, 0.442298, 0.4436866, 0.4450752, 0.4464637, 0.4478523, 0.4492409, 0.4506447, 0.4520333, 0.4534371, 0.4548409, 0.4562448, 0.4576486, 0.4590677, 0.4604715, 0.4618906, 0.4633097, 0.4647288, 0.4661631, 0.4675822, 0.4690166, 0.4704356, 0.47187, 0.4733043, 0.4747539, 0.4761883, 0.4776379, 0.4790875, 0.4805371, 0.4819867, 0.4834363, 0.4848859, 0.4863508, 0.4878157, 0.4892805, 0.4907454, 0.4922103, 0.4936904, 0.4951553, 0.4966354, 0.4981155, 0.4995956, 0.501091, 0.5025711, 0.5040665, 0.5055467, 0.507042, 0.5085527, 0.5100481, 0.5115435, 0.5130541, 0.5145647, 0.5160754, 0.517586, 0.5190967, 0.5206226, 0.5221485, 0.5236591, 0.525185, 0.5267262, 0.5282521, 0.529778, 0.5313191, 0.5328603, 0.5344015, 0.5359426, 0.537499, 0.5390402, 0.5405966, 0.542153, 0.5437095, 0.5452659, 0.5468223, 0.548394, 0.5499657, 0.5515373, 0.553109, 0.5546807, 0.5562524, 0.5578393, 0.5594263, 0.5610132, 0.5626001, 0.5641871, 0.565774, 0.5673762, 0.5689784, 0.5705806, 0.5721828, 0.573785, 0.5754025, 0.5770047, 0.5786221, 0.5802396, 0.581857, 0.5834897, 0.5851072, 0.5867399, 0.5883726, 0.5900053, 0.5916381, 0.5932708, 0.5949187, 0.5965667, 0.5982147, 0.5998627, 0.6015106, 0.6031586, 0.6048219, 0.6064851, 0.6081483, 0.6098116, 0.6114748, 0.6131533, 0.6148165, 0.616495, 0.6181735, 0.619852, 0.6215457, 0.6232242, 0.624918, 0.6266117, 0.6283055, 0.6299992, 0.631693, 0.633402, 0.635111, 0.63682, 0.638529, 0.640238, 0.6419471, 0.6436713, 0.6453956, 0.6471199, 0.6488441, 0.6505684, 0.6523079, 0.6540322, 0.6557717, 0.6575113, 0.6592508, 0.6610056, 0.6627451, 0.6644999, 0.6662547, 0.6680095, 0.6697642, 0.6715343, 0.6732891, 0.6750591, 0.6768292, 0.6785992, 0.6803845, 0.6821546, 0.6839399, 0.6857252, 0.6875105, 0.6892958, 0.6910811, 0.6928817, 0.6946822, 0.6964675, 0.6982834, 0.7000839, 0.7018845, 0.7037003, 0.7055161, 0.707332, 0.7091478, 0.7109636, 0.7127947, 0.7146105, 0.7164416, 0.7182727, 0.720119, 0.7219501, 0.7237964, 0.7256275, 0.7274739, 0.7293355, 0.7311818, 0.7330282, 0.7348898, 0.7367514, 0.738613, 0.7404746, 0.7423514, 0.744213, 0.7460899, 0.7479667, 0.7498436, 0.7517205, 0.7536126, 0.7554894, 0.7573816, 0.7592737, 0.7611658, 0.7630732, 0.7649653, 0.7668727, 0.76878, 0.7706874, 0.7725948, 0.7745174, 0.7764248, 0.7783474, 0.7802701, 0.7821927, 0.7841306, 0.7860533, 0.7879911, 0.789929, 0.7918669, 0.7938048, 0.795758, 0.7976959, 0.799649, 0.8016022, 0.8035554, 0.8055238, 0.8074769, 0.8094453, 0.8114137, 0.8133822, 0.8153506, 0.8173342, 0.8193179, 0.8212863, 0.82327, 0.8252689, 0.8272526, 0.8292515, 0.8312352, 0.8332341, 0.8352331, 0.8372473, 0.8392462, 0.8412604, 0.8432746, 0.8452888, 0.847303, 0.8493172, 0.8513466, 0.8533761, 0.8554055, 0.857435, 0.8594644, 0.8614939, 0.8635386, 0.8655833, 0.867628, 0.8696727, 0.8717327, 0.8737774, 0.8758373, 0.8778973, 0.8799573, 0.8820325, 0.8840925, 0.8861677, 0.8882429, 0.8903182, 0.8923934, 0.8944839, 0.8965591, 0.8986496, 0.9007401, 0.9028305, 0.9049363, 0.9070268, 0.9091325, 0.9112383, 0.913344, 0.915465, 0.9175708, 0.9196918, 0.9218128, 0.9239338, 0.9260548, 0.9281758, 0.930312, 0.9324483, 0.9345846, 0.9367208, 0.9388571, 0.9410086, 0.9431601, 0.9453117, 0.9474632, 0.9496147, 0.9517815, 0.953933, 0.9560998, 0.9582666, 0.9604334, 0.9626154, 0.9647822, 0.9669642, 0.9691463, 0.9713283, 0.9735256, 0.9757076, 0.9779049, 0.9801022, 0.9822995, 0.9844968, 0.9867094, 0.988922, 0.9911345, 0.9933471, 0.9955596, 0.9977722, 1.0",
        "ICC:Technology": "CRT",
        "File Size": "14219 bytes",
        "Exif IFD0:Resolution Unit": "Inch",
        "ICC:Color space": "RGB",
        "ICC:Blue TRC": "0.0, 0.0000763, 0.0001526, 0.0002289, 0.0003052, 0.0003815, 0.0004578, 0.0005341, 0.0006104, 0.0006867, 0.000763, 0.0008392, 0.0009003, 0.0009766, 0.0010529, 0.0011292, 0.0012055, 0.0012818, 0.0013581, 0.0014343, 0.0015106, 0.0015869, 0.0016632, 0.0017395, 0.0018158, 0.0018921, 0.0019684, 0.0020447, 0.002121, 0.0021973, 0.0022736, 0.0023499, 0.0024262, 0.0025025, 0.0025788, 0.0026551, 0.0027161, 0.0027924, 0.0028687, 0.002945, 0.0030213, 0.0030976, 0.0031739, 0.0032502, 0.0033417, 0.003418, 0.0034943, 0.0035859, 0.0036622, 0.0037537, 0.00383, 0.0039216, 0.0040131, 0.0041047, 0.0041962, 0.0042878, 0.0043793, 0.0044709, 0.0045624, 0.0046693, 0.0047608, 0.0048524, 0.0049592, 0.005066, 0.0051575, 0.0052644, 0.0053712, 0.005478, 0.0055848, 0.0056916, 0.0057984, 0.0059052, 0.0060273, 0.0061341, 0.0062562, 0.006363, 0.0064851, 0.0066072, 0.0067292, 0.0068513, 0.0069734, 0.0070954, 0.0072175, 0.0073396, 0.0074617, 0.007599, 0.0077211, 0.0078584, 0.0079957, 0.0081178, 0.0082551, 0.0083925, 0.0085298, 0.0086671, 0.0088045, 0.008957, 0.0090944, 0.0092317, 0.0093843, 0.0095369, 0.0096742, 0.0098268, 0.0099794, 0.010132, 0.0102846, 0.0104372, 0.0105898, 0.0107576, 0.0109102, 0.0110628, 0.0112306, 0.0113985, 0.0115511, 0.0117189, 0.0118868, 0.0120546, 0.0122225, 0.0124056, 0.0125734, 0.0127413, 0.0129244, 0.0130922, 0.0132753, 0.0134585, 0.0136416, 0.0138247, 0.0140078, 0.0141909, 0.014374, 0.0145571, 0.0147555, 0.0149386, 0.0151369, 0.0153201, 0.0155184, 0.0157168, 0.0159152, 0.0161135, 0.0163119, 0.0165255, 0.0167239, 0.0169223, 0.0171359, 0.0173495, 0.0175479, 0.0177615, 0.0179751, 0.0181888, 0.0184024, 0.018616, 0.0188449, 0.0190585, 0.0192874, 0.019501, 0.0197299, 0.0199588, 0.0201877, 0.0204166, 0.0206455, 0.0208743, 0.0211032, 0.0213474, 0.0215763, 0.0218204, 0.0220645, 0.0222934, 0.0225376, 0.0227817, 0.0230259, 0.0232853, 0.0235294, 0.0237736, 0.024033, 0.0242771, 0.0245365, 0.0247959, 0.0250553, 0.0253147, 0.0255741, 0.0258335, 0.0261082, 0.0263676, 0.026627, 0.0269017, 0.0271763, 0.027451, 0.0277256, 0.0280003, 0.028275, 0.0285496, 0.0288243, 0.0291142, 0.0293889, 0.0296788, 0.0299687, 0.0302586, 0.0305486, 0.0308385, 0.0311284, 0.0314183, 0.0317235, 0.0320134, 0.0323186, 0.0326238, 0.032929, 0.0332341, 0.0335393, 0.0338445, 0.0341497, 0.0344549, 0.0347753, 0.0350805, 0.0354009, 0.0357214, 0.0360418, 0.0363622, 0.0366827, 0.0370031, 0.0373388, 0.0376593, 0.037995, 0.0383154, 0.0386511, 0.0389868, 0.0393225, 0.0396582, 0.0399939, 0.0403449, 0.0406806, 0.0410315, 0.0413825, 0.0417182, 0.0420691, 0.0424201, 0.042771, 0.0431373, 0.0434882, 0.0438392, 0.0442054, 0.0445716, 0.0449226, 0.0452888, 0.045655, 0.0460212, 0.0464027, 0.0467689, 0.0471504, 0.0475166, 0.0478981, 0.0482795, 0.048661, 0.0490425, 0.049424, 0.0498054, 0.0501869, 0.0505837, 0.0509804, 0.0513619, 0.0517586, 0.0521553, 0.0525521, 0.0529488, 0.0533608, 0.0537575, 0.0541695, 0.0545663, 0.0549783, 0.0553902, 0.0558022, 0.0562142, 0.0566262, 0.0570535, 0.0574655, 0.0578927, 0.05832, 0.058732, 0.0591592, 0.0595865, 0.060029, 0.0604562, 0.0608835, 0.061326, 0.0617533, 0.0621958, 0.0626383, 0.0630808, 0.0635233, 0.0639811, 0.0644236, 0.0648661, 0.0653239, 0.0657816, 0.0662394, 0.0666972, 0.067155, 0.0676127, 0.0680705, 0.0685435, 0.0690013, 0.0694743, 0.0699474, 0.0704204, 0.0708934, 0.0713664, 0.0718395, 0.0723278, 0.0728008, 0.0732891, 0.0737774, 0.0742657, 0.0747539, 0.0752422, 0.0757305, 0.0762188, 0.0767224, 0.0772259, 0.0777142, 0.0782177, 0.0787213, 0.0792401, 0.0797436, 0.0802472, 0.080766, 0.0812696, 0.0817884, 0.0823072, 0.082826, 0.0833448, 0.0838636, 0.0843977, 0.0849165, 0.0854505, 0.0859846, 0.0865187, 0.0870527, 0.0875868, 0.0881209, 0.0886549, 0.0892042, 0.0897536, 0.0902876, 0.090837, 0.0913863, 0.0919356, 0.0925002, 0.0930495, 0.0936141, 0.0941634, 0.094728, 0.0952926, 0.0958572, 0.0964218, 0.0970016, 0.0975662, 0.098146, 0.0987106, 0.0992905, 0.0998703, 0.1004501, 0.10103, 0.1016251, 0.1022049, 0.1028, 0.1033799, 0.103975, 0.1045701, 0.1051652, 0.1057755, 0.1063706, 0.106981, 0.1075761, 0.1081865, 0.1087968, 0.1094072, 0.1100175, 0.1106279, 0.1112535, 0.1118639, 0.1124895, 0.1131151, 0.1137407, 0.1143664, 0.114992, 0.1156176, 0.1162585, 0.1168841, 0.117525, 0.1181659, 0.1188067, 0.1194476, 0.1200885, 0.1207446, 0.1213855, 0.1220417, 0.1226978, 0.1233539, 0.1240101, 0.1246662, 0.1253223, 0.1259937, 0.1266499, 0.1273213, 0.1279927, 0.1286641, 0.1293355, 0.1300069, 0.1306935, 0.1313649, 0.1320516, 0.1327382, 0.1334096, 0.1341115, 0.1347982, 0.1354849, 0.1361868, 0.1368734, 0.1375753, 0.1382773, 0.1389792, 0.1396811, 0.140383, 0.1411002, 0.1418021, 0.1425193, 0.1432364, 0.1439536, 0.1446708, 0.145388, 0.1461204, 0.1468376, 0.14757, 0.1483024, 0.1490349, 0.1497673, 0.1504997, 0.1512322, 0.1519799, 0.1527123, 0.15346, 0.1542077, 0.1549554, 0.1557031, 0.1564508, 0.1572137, 0.1579767, 0.1587243, 0.1594873, 0.1602502, 0.1610132, 0.1617914, 0.1625544, 0.1633326, 0.1640955, 0.1648737, 0.1656519, 0.1664302, 0.1672236, 0.1680018, 0.1687953, 0.1695735, 0.170367, 0.1711604, 0.1719539, 0.1727474, 0.1735561, 0.1743496, 0.1751583, 0.175967, 0.1767758, 0.1775845, 0.1783932, 0.1792172, 0.1800259, 0.1808499, 0.1816739, 0.1824826, 0.1833219, 0.1841459, 0.1849699, 0.1858091, 0.1866331, 0.1874723, 0.1883116, 0.1891508, 0.1900053, 0.1908446, 0.1916838, 0.1925383, 0.1933928, 0.1942473, 0.1951019, 0.1959564, 0.1968261, 0.1976806, 0.1985504, 0.1994202, 0.2002899, 0.2011597, 0.2020294, 0.2028992, 0.2037842, 0.2046693, 0.205539, 0.206424, 0.2073243, 0.2082094, 0.2090944, 0.2099947, 0.2108949, 0.21178, 0.2126802, 0.2135958, 0.2144961, 0.2153964, 0.2163119, 0.2172274, 0.2181277, 0.2190585, 0.2199741, 0.2208896, 0.2218051, 0.2227359, 0.2236667, 0.2245975, 0.2255283, 0.2264591, 0.2273899, 0.228336, 0.2292821, 0.2302129, 0.2311589, 0.232105, 0.2330663, 0.2340124, 0.2349737, 0.2359197, 0.2368811, 0.2378424, 0.2388037, 0.239765, 0.2407416, 0.2417029, 0.2426795, 0.2436561, 0.2446326, 0.2456092, 0.2466011, 0.2475776, 0.2485695, 0.249546, 0.2505379, 0.2515297, 0.2525368, 0.2535286, 0.2545357, 0.2555276, 0.2565347, 0.2575418, 0.2585489, 0.259556, 0.2605783, 0.2615854, 0.2626078, 0.2636301, 0.2646525, 0.2656748, 0.2667124, 0.2677348, 0.2687724, 0.26981, 0.2708324, 0.2718853, 0.2729229, 0.2739605, 0.2750134, 0.276051, 0.2771038, 0.2781567, 0.2792248, 0.2802777, 0.2813306, 0.2823987, 0.2834668, 0.284535, 0.2856031, 0.2866712, 0.2877394, 0.2888228, 0.2899062, 0.2909743, 0.2920577, 0.2931563, 0.2942397, 0.2953231, 0.2964218, 0.2975204, 0.2986191, 0.2997177, 0.3008164, 0.301915, 0.3030289, 0.3041428, 0.3052567, 0.3063706, 0.3074846, 0.3085985, 0.3097124, 0.3108415, 0.3119707, 0.3130999, 0.314229, 0.3153582, 0.3165026, 0.3176318, 0.3187762, 0.3199207, 0.3210651, 0.3222095, 0.3233539, 0.3245136, 0.3256733, 0.3268177, 0.3279774, 0.3291371, 0.330312, 0.3314717, 0.3326467, 0.3338216, 0.3349966, 0.3361715, 0.3373465, 0.3385214, 0.3397116, 0.3408865, 0.3420768, 0.343267, 0.3444724, 0.3456626, 0.3468528, 0.3480583, 0.3492638, 0.3504692, 0.3516747, 0.3528801, 0.3541009, 0.3553063, 0.356527, 0.3577478, 0.3589685, 0.3601892, 0.3614252, 0.3626459, 0.3638819, 0.3651179, 0.3663539, 0.3675898, 0.3688411, 0.3700771, 0.3713283, 0.3725795, 0.3738308, 0.375082, 0.3763333, 0.3775998, 0.378851, 0.3801175, 0.381384, 0.3826505, 0.3839322, 0.3851987, 0.3864805, 0.387747, 0.3890288, 0.3903105, 0.3916075, 0.3928893, 0.3941863, 0.3954681, 0.3967651, 0.3980621, 0.3993744, 0.4006714, 0.4019837, 0.4032807, 0.404593, 0.4059052, 0.4072175, 0.4085451, 0.4098573, 0.4111849, 0.4125124, 0.4138399, 0.4151675, 0.416495, 0.4178378, 0.4191806, 0.4205234, 0.4218662, 0.423209, 0.4245518, 0.4259098, 0.4272526, 0.4286107, 0.4299687, 0.4313268, 0.4326848, 0.4340581, 0.4354314, 0.4367895, 0.4381628, 0.4395514, 0.4409247, 0.442298, 0.4436866, 0.4450752, 0.4464637, 0.4478523, 0.4492409, 0.4506447, 0.4520333, 0.4534371, 0.4548409, 0.4562448, 0.4576486, 0.4590677, 0.4604715, 0.4618906, 0.4633097, 0.4647288, 0.4661631, 0.4675822, 0.4690166, 0.4704356, 0.47187, 0.4733043, 0.4747539, 0.4761883, 0.4776379, 0.4790875, 0.4805371, 0.4819867, 0.4834363, 0.4848859, 0.4863508, 0.4878157, 0.4892805, 0.4907454, 0.4922103, 0.4936904, 0.4951553, 0.4966354, 0.4981155, 0.4995956, 0.501091, 0.5025711, 0.5040665, 0.5055467, 0.507042, 0.5085527, 0.5100481, 0.5115435, 0.5130541, 0.5145647, 0.5160754, 0.517586, 0.5190967, 0.5206226, 0.5221485, 0.5236591, 0.525185, 0.5267262, 0.5282521, 0.529778, 0.5313191, 0.5328603, 0.5344015, 0.5359426, 0.537499, 0.5390402, 0.5405966, 0.542153, 0.5437095, 0.5452659, 0.5468223, 0.548394, 0.5499657, 0.5515373, 0.553109, 0.5546807, 0.5562524, 0.5578393, 0.5594263, 0.5610132, 0.5626001, 0.5641871, 0.565774, 0.5673762, 0.5689784, 0.5705806, 0.5721828, 0.573785, 0.5754025, 0.5770047, 0.5786221, 0.5802396, 0.581857, 0.5834897, 0.5851072, 0.5867399, 0.5883726, 0.5900053, 0.5916381, 0.5932708, 0.5949187, 0.5965667, 0.5982147, 0.5998627, 0.6015106, 0.6031586, 0.6048219, 0.6064851, 0.6081483, 0.6098116, 0.6114748, 0.6131533, 0.6148165, 0.616495, 0.6181735, 0.619852, 0.6215457, 0.6232242, 0.624918, 0.6266117, 0.6283055, 0.6299992, 0.631693, 0.633402, 0.635111, 0.63682, 0.638529, 0.640238, 0.6419471, 0.6436713, 0.6453956, 0.6471199, 0.6488441, 0.6505684, 0.6523079, 0.6540322, 0.6557717, 0.6575113, 0.6592508, 0.6610056, 0.6627451, 0.6644999, 0.6662547, 0.6680095, 0.6697642, 0.6715343, 0.6732891, 0.6750591, 0.6768292, 0.6785992, 0.6803845, 0.6821546, 0.6839399, 0.6857252, 0.6875105, 0.6892958, 0.6910811, 0.6928817, 0.6946822, 0.6964675, 0.6982834, 0.7000839, 0.7018845, 0.7037003, 0.7055161, 0.707332, 0.7091478, 0.7109636, 0.7127947, 0.7146105, 0.7164416, 0.7182727, 0.720119, 0.7219501, 0.7237964, 0.7256275, 0.7274739, 0.7293355, 0.7311818, 0.7330282, 0.7348898, 0.7367514, 0.738613, 0.7404746, 0.7423514, 0.744213, 0.7460899, 0.7479667, 0.7498436, 0.7517205, 0.7536126, 0.7554894, 0.7573816, 0.7592737, 0.7611658, 0.7630732, 0.7649653, 0.7668727, 0.76878, 0.7706874, 0.7725948, 0.7745174, 0.7764248, 0.7783474, 0.7802701, 0.7821927, 0.7841306, 0.7860533, 0.7879911, 0.789929, 0.7918669, 0.7938048, 0.795758, 0.7976959, 0.799649, 0.8016022, 0.8035554, 0.8055238, 0.8074769, 0.8094453, 0.8114137, 0.8133822, 0.8153506, 0.8173342, 0.8193179, 0.8212863, 0.82327, 0.8252689, 0.8272526, 0.8292515, 0.8312352, 0.8332341, 0.8352331, 0.8372473, 0.8392462, 0.8412604, 0.8432746, 0.8452888, 0.847303, 0.8493172, 0.8513466, 0.8533761, 0.8554055, 0.857435, 0.8594644, 0.8614939, 0.8635386, 0.8655833, 0.867628, 0.8696727, 0.8717327, 0.8737774, 0.8758373, 0.8778973, 0.8799573, 0.8820325, 0.8840925, 0.8861677, 0.8882429, 0.8903182, 0.8923934, 0.8944839, 0.8965591, 0.8986496, 0.9007401, 0.9028305, 0.9049363, 0.9070268, 0.9091325, 0.9112383, 0.913344, 0.915465, 0.9175708, 0.9196918, 0.9218128, 0.9239338, 0.9260548, 0.9281758, 0.930312, 0.9324483, 0.9345846, 0.9367208, 0.9388571, 0.9410086, 0.9431601, 0.9453117, 0.9474632, 0.9496147, 0.9517815, 0.953933, 0.9560998, 0.9582666, 0.9604334, 0.9626154, 0.9647822, 0.9669642, 0.9691463, 0.9713283, 0.9735256, 0.9757076, 0.9779049, 0.9801022, 0.9822995, 0.9844968, 0.9867094, 0.988922, 0.9911345, 0.9933471, 0.9955596, 0.9977722, 1.0",
        "File Modified Date": "Mon Apr 07 02:13:43 +00:00 2025",
        "Layer Groups Enabled ID": "1 1",
        "Image Height": "112 pixels",
        "Pixel Aspect Ratio": "1.0",
        "Flags 0": "64",
        "ICC:Primary Platform": "Microsoft Corporation",
        "Print Scale": "Centered, Scale 1.0",
        "ICC:Red Colorant": "(0.4361, 0.2225, 0.0139)",
        "tiff:ImageWidth": "90",
        "Exif IFD0:Y Resolution": "72 dots per inch",
        "Flags 1": "0",
        "Number of Tables": "4 Huffman tables",
        "Slices": "제목 없음-2 (0,0,112,90) 1 Slices",
        "ICC:Profile Copyright": "Copyright (c) 1998 Hewlett-Packard Company",
        "ICC:Class": "Display Device",
        "ICC:Measurement": "1931 2° Observer, Backing (0, 0, 0), Geometry Unknown, Flare 1%, Illuminant D65",
        "Exif SubIFD:Exif Image Width": "90 pixels",
        "ICC:Device manufacturer": "IEC",
        "Print Style": "[434 values]",
        "ICC:Viewing Conditions": "view (0x76696577): 36 bytes",
        "ICC:CMM Type": "Lino",
        "Thumbnail Data": "JpegRGB, 90x112, Decomp 30464 bytes, 1572865 bpp, 1074 bytes",
        "resourceName": "b'tmpc3ussv50'",
        "Color Halftoning Information": "[72 values]",
        "Exif IFD0:Orientation": "Top, left side (Horizontal / normal)",
        "Color Transfer Functions": "[112 values]",
        "Layer State Information": "0 1",
        "Color Transform": "YCbCr",
        "X-TIKA:Parsed-By": [
            "org.apache.tika.parser.DefaultParser",
            "org.apache.tika.parser.image.JpegParser",
            "org.apache.tika.parser.ocr.TesseractOCRParser",
        ],
        "XMP Value Count": "20",
        "Global Angle": "120",
        "Exif IFD0:Software": "Adobe Photoshop CS5.1 Windows",
        "ICC:Tag Count": "17",
        "Exif IFD0:Date/Time": "2015:05:08 10:32:14",
        "ICC:Device model": "sRGB",
        "ICC:Device Model Description": "IEC 61966-2.1 Default RGB colour space - sRGB",
        "Data Precision": "8 bits",
        "tiff:ImageLength": "112",
        "Layer Selection IDs": "0 1 0 0 0 2",
        "dcterms:created": "2015-05-08T10:32:14",
        "dcterms:modified": "2015-05-08T10:32:14",
        "ICC:Profile Date/Time": "1998:02:09 06:49:00",
        "xmpMM:DocumentID": "xmp.did:17ACF1BC18F5E41186DCECFA30DBF83A",
        "Exif SubIFD:Color Space": "sRGB",
        "Print Info 2": "[171 values]",
        "ICC:Profile Description": "sRGB IEC61966-2.1",
        "Global Altitude": "30",
        "Exif Thumbnail:Y Resolution": "72 dots per inch",
        "Exif Thumbnail:Resolution Unit": "Inch",
        "Grid and Guides Information": "0 0 0 1 0 0 2 64 0 0 2 64 0 0 0 0",
        "File Name": "apache-tika-16196145968302569733.tmp",
        "Content-Length": "14219",
        "Content-Type": "image/jpeg",
        "JPEG Quality": "12 (Maximum), Standard format, 3 scans",
        "ICC:XYZ values": "0.964 1 0.825",
        "tiff:XResolution": "72.0",
        "DCT Encode Version": "25600",
        "Exif Thumbnail:Thumbnail Length": "1074 bytes",
        "ICC:Media Black Point": "(0, 0, 0)",
        "Print Flags": "0 0 0 0 0 0 0 0 1",
        "Exif SubIFD:Exif Image Height": "112 pixels",
        "Image Width": "90 pixels",
        "Print Flags Information": "0 1 0 0 0 0 0 0 0 2",
        "Exif Thumbnail:Compression": "JPEG (old-style)",
        "Content-Type-Parser-Override": "image/ocr-jpeg",
        "URL List": "0",
        "ICC:Viewing Conditions Description": "Reference Viewing Condition in IEC61966-2.1",
    },
    "attachments": {},
}
