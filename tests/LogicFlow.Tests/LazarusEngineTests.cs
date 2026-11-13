using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Media;
using LogicFlow.Dashboard;
using LogicFlow.Lazarus;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LogicFlow.Tests;

public class LazarusEngineTests
{
    [Fact]
    public void FileCarver_DetectsSignatures_Png_Jpg_Pdf_Zip()
    {
        var carver = new FileCarver(NullLogger<FileCarver>.Instance);

        // Construct mock disk sector buffer with multiple embedded file headers
        byte[] buffer = new byte[4096];

        // 1. PNG at offset 100 with IEND trailer at offset 300
        byte[] pngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        byte[] pngTrailer = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
        Buffer.BlockCopy(pngHeader, 0, buffer, 100, pngHeader.Length);
        Buffer.BlockCopy(pngTrailer, 0, buffer, 300, pngTrailer.Length);

        // 2. JPEG at offset 600 with EOI trailer at offset 900
        byte[] jpgHeader = [0xFF, 0xD8, 0xFF, 0xE0];
        byte[] jpgTrailer = [0xFF, 0xD9];
        Buffer.BlockCopy(jpgHeader, 0, buffer, 600, jpgHeader.Length);
        Buffer.BlockCopy(jpgTrailer, 0, buffer, 900, jpgTrailer.Length);

        // 3. PDF at offset 1200 with %%EOF at offset 1500
        byte[] pdfHeader = [0x25, 0x50, 0x44, 0x46];
        byte[] pdfTrailer = [0x25, 0x25, 0x45, 0x4F, 0x46];
        Buffer.BlockCopy(pdfHeader, 0, buffer, 1200, pdfHeader.Length);
        Buffer.BlockCopy(pdfTrailer, 0, buffer, 1500, pdfTrailer.Length);

        // 4. ZIP at offset 2000
        byte[] zipHeader = [0x50, 0x4B, 0x03, 0x04];
        Buffer.BlockCopy(zipHeader, 0, buffer, 2000, zipHeader.Length);

        var results = carver.ScanBuffer(buffer, 0);

        Assert.Equal(4, results.Count);

        var png = results.First(r => r.Extension == "png");
        Assert.Equal(100, png.ByteOffset);
        Assert.Equal("Images", png.Category);
        Assert.Contains("100%", png.Confidence);
        Assert.Equal(208, png.EstimatedSizeBytes);

        var jpg = results.First(r => r.Extension == "jpg");
        Assert.Equal(600, jpg.ByteOffset);
        Assert.Equal("Images", jpg.Category);
        Assert.Contains("100%", jpg.Confidence);
        Assert.Equal(302, jpg.EstimatedSizeBytes);

        var pdf = results.First(r => r.Extension == "pdf");
        Assert.Equal(1200, pdf.ByteOffset);
        Assert.Equal("Documents", pdf.Category);
        Assert.Contains("High", pdf.Confidence);
        Assert.Equal(305, pdf.EstimatedSizeBytes);

        var zip = results.First(r => r.Extension == "zip");
        Assert.Equal(2000, zip.ByteOffset);
        Assert.Equal("Archives", zip.Category);
        Assert.True(zip.EstimatedSizeBytes > 0);
    }

    [Fact]
    public void FileCarver_RefineCarvedBytes_TrimsTrailingSlack()
    {
        byte[] pngWithSlack = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
            0xAA, 0xBB, 0xCC, 0xDD
        ];
        var refinedPng = FileCarver.RefineCarvedBytes(pngWithSlack, "png");
        Assert.Equal(20, refinedPng.Length);
        Assert.Equal(0x82, refinedPng[^1]);

        byte[] jpgWithSlack = [
            0xFF, 0xD8, 0xFF, 0xE0, 0x12, 0x34, 0xFF, 0xD9,
            0xDE, 0xAD, 0xBE, 0xEF
        ];
        var refinedJpg = FileCarver.RefineCarvedBytes(jpgWithSlack, "jpg");
        Assert.Equal(8, refinedJpg.Length);
        Assert.Equal(0xD9, refinedJpg[^1]);
    }

    [Fact]
    public void FileCarver_GenerateValidFallback_CreatesValidStructures()
    {
        var pngBytes = FileCarver.GenerateValidFileBytes("png", "PNG Image", 1024);
        Assert.NotNull(pngBytes);
        Assert.True(pngBytes.Length >= 20);
        Assert.Equal(0x89, pngBytes[0]);
        Assert.Equal(0x50, pngBytes[1]);
        Assert.Equal(0x4E, pngBytes[2]);
        Assert.Equal(0x47, pngBytes[3]);

        var pdfBytes = FileCarver.GenerateValidFileBytes("pdf", "PDF Document", 2048);
        Assert.NotNull(pdfBytes);
        var pdfStr = System.Text.Encoding.UTF8.GetString(pdfBytes);
        Assert.StartsWith("%PDF-", pdfStr);
        Assert.Contains("%%EOF", pdfStr);

        var zipBytes = FileCarver.GenerateValidFileBytes("zip", "ZIP Archive", 4096);
        Assert.NotNull(zipBytes);
        Assert.Equal(0x50, zipBytes[0]);
        Assert.Equal(0x4B, zipBytes[1]);

        var gifBytes = FileCarver.GenerateValidFileBytes("gif", "GIF89a Image", 512);
        Assert.NotNull(gifBytes);
        Assert.Equal(0x47, gifBytes[0]); // 'G'
        Assert.Equal(0x49, gifBytes[1]); // 'I'
        Assert.Equal(0x46, gifBytes[2]); // 'F'
        Assert.Equal(0x3B, gifBytes[^1]); // GIF terminator

        var mp4Bytes = FileCarver.GenerateValidFileBytes("mp4", "MP4 Video", 8192);
        Assert.NotNull(mp4Bytes);
        Assert.Equal(0x66, mp4Bytes[4]); // 'f'
        Assert.Equal(0x74, mp4Bytes[5]); // 't'
        Assert.Equal(0x79, mp4Bytes[6]); // 'y'
        Assert.Equal(0x70, mp4Bytes[7]); // 'p'

        var mp3Bytes = FileCarver.GenerateValidFileBytes("mp3", "MP3 Audio", 4096);
        Assert.NotNull(mp3Bytes);
        Assert.Equal(0x49, mp3Bytes[0]); // 'I'
        Assert.Equal(0x44, mp3Bytes[1]); // 'D'
        Assert.Equal(0x33, mp3Bytes[2]); // '3'

        var sqliteBytes = FileCarver.GenerateValidFileBytes("sqlite", "SQLite Database", 1024);
        Assert.NotNull(sqliteBytes);
        var sqliteMagic = System.Text.Encoding.ASCII.GetString(sqliteBytes, 0, 16);
        Assert.Equal("SQLite format 3\0", sqliteMagic);
    }

    [Fact]
    public async Task LazarusRecoveryEngine_ScanVolumeSignaturesAsync_ThrowsUnauthorizedAccess_OnUnprivilegedOrInvalidVolume()
    {
        var engine = new LazarusRecoveryEngine();

        // Scan non-existent or unprivileged volume — must honestly fail and require elevation, never generate deceptive fake signatures
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
        {
            await engine.ScanVolumeSignaturesAsync("Z:\\NonExistentDrive", 0, 4096);
        });
    }

    [Fact]
    public async Task LazarusRecoveryEngine_RecoverFileAsync_FailsHonestly_WhenSectorAccessFails()
    {
        var engine = new LazarusRecoveryEngine();
        string testFolder = Path.Combine(Path.GetTempPath(), "LogicFlow_Lazarus_Test_" + Guid.NewGuid().ToString("N"));

        try
        {
            var header = new CarvedFileHeader
            {
                Extension = "png",
                FileType = "PNG Image",
                ByteOffset = 0x00021B4F,
                HeaderSize = 8,
                EstimatedSizeBytes = 512,
                Category = "Images",
                Confidence = "High (Header Validated)"
            };

            var result = await engine.RecoverFileAsync(
                null, "C:", header, testFolder, 1);

            Assert.False(result.Success);
            Assert.Equal(0, result.BytesWritten);
            Assert.Contains("No raw bytes could be extracted", result.Error);
            Assert.False(File.Exists(result.FilePath));
        }
        finally
        {
            if (Directory.Exists(testFolder))
            {
                Directory.Delete(testFolder, true);
            }
        }
    }

    [Fact]
    public async Task LazarusRecoveryEngine_RecoverFileAsync_MultiFormatBatch_FailsHonestlyWithoutDirectAccess()
    {
        var engine = new LazarusRecoveryEngine();
        string testFolder = Path.Combine(Path.GetTempPath(), "LogicFlow_Lazarus_BatchTest_" + Guid.NewGuid().ToString("N"));

        try
        {
            var mockHeaders = new[]
            {
                new CarvedFileHeader { Extension = "png", FileType = "PNG Image", ByteOffset = 0x1000 },
                new CarvedFileHeader { Extension = "pdf", FileType = "PDF Document", ByteOffset = 0x2000 },
                new CarvedFileHeader { Extension = "zip", FileType = "ZIP Archive", ByteOffset = 0x3000 },
            };

            for (int i = 0; i < mockHeaders.Length; i++)
            {
                var result = await engine.RecoverFileAsync(null, "C:", mockHeaders[i], testFolder, i + 1);
                Assert.False(result.Success);
                Assert.Equal(0, result.BytesWritten);
            }
        }
        finally
        {
            if (Directory.Exists(testFolder))
            {
                Directory.Delete(testFolder, true);
            }
        }
    }

    [Fact]
    public void CarvedFileItem_FormattingAndSelection_FunctionsAccurately()
    {
        var header = new CarvedFileHeader
        {
            Extension = "pdf",
            FileType = "PDF Document",
            ByteOffset = 0x00084C20,
            HeaderSize = 4,
            EstimatedSizeBytes = 1048576,
            Category = "Documents",
            Confidence = "High (%%EOF Validated)"
        };

        var item = new CarvedFileItem
        {
            Header = header,
            DriveSource = "C:",
            IsSelected = true
        };

        Assert.True(item.IsSelected);
        Assert.Equal("PDF", item.Extension);
        Assert.Equal("PDF Document", item.FileType);
        Assert.Equal("Documents", item.Category);
        Assert.Equal("0x00084C20", item.OffsetFormatted);
        Assert.Equal("1 MB", item.SizeFormatted);
        Assert.Equal("📄", item.Icon);
        Assert.NotNull(item.TypeBadgeBrush);
        Assert.NotNull(item.ConfidenceBadgeBrush);

        bool propertyChangedRaised = false;
        item.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(CarvedFileItem.IsSelected))
                propertyChangedRaised = true;
        };

        item.IsSelected = false;
        Assert.False(item.IsSelected);
        Assert.True(propertyChangedRaised);
    }

    [Fact]
    public void FileCarver_ExtractImageDimensions_ExtractsPngJpgBmpGifAccurately()
    {
        // 1. PNG Test
        var pngBytes = FileCarver.GenerateValidFileBytes("png", "PNG Image", 0);
        var (pngW, pngH, pngSpec) = FileCarver.ExtractImageDimensions(pngBytes, "png");
        Assert.Equal(64, pngW);
        Assert.Equal(64, pngH);
        Assert.Contains("RGB", pngSpec);

        // 2. BMP Test
        var bmpBytes = FileCarver.GenerateValidFileBytes("bmp", "Windows Bitmap", 0);
        var (bmpW, bmpH, bmpSpec) = FileCarver.ExtractImageDimensions(bmpBytes, "bmp");
        Assert.Equal(64, bmpW);
        Assert.Equal(64, bmpH);
        Assert.Contains("24-bit", bmpSpec);

        // 3. GIF Test
        var gifBytes = FileCarver.GenerateValidFileBytes("gif", "GIF Image", 0);
        var (gifW, gifH, gifSpec) = FileCarver.ExtractImageDimensions(gifBytes, "gif");
        Assert.Equal(32, gifW);
        Assert.Equal(32, gifH);
        Assert.Contains("GIF", gifSpec);

        // 4. JPEG Test
        var jpgBytes = FileCarver.GenerateValidFileBytes("jpg", "JPEG Image", 0);
        var (jpgW, jpgH, jpgSpec) = FileCarver.ExtractImageDimensions(jpgBytes, "jpg");
        Assert.Equal(64, jpgW);
        Assert.Equal(64, jpgH);
        Assert.Contains("JPEG", jpgSpec);
    }

    [Fact]
    public void FileCarver_FormatArchiveManifest_ParsesZipCorrectly()
    {
        using var ms = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
        {
            var e1 = archive.CreateEntry("word/document.xml");
            using (var sw = new StreamWriter(e1.Open())) sw.Write("<xml>Test Word Content</xml>");

            var e2 = archive.CreateEntry("[Content_Types].xml");
            using (var sw = new StreamWriter(e2.Open())) sw.Write("<Types/>");
        }

        var zipBytes = ms.ToArray();
        string manifest = FileCarver.FormatArchiveManifest(zipBytes);

        Assert.Contains("ARCHIVE / COMPOUND DOCUMENT INSPECTOR", manifest);
        Assert.Contains("word/document.xml", manifest);
        Assert.Contains("[Content_Types].xml", manifest);
    }

    [Fact]
    public void FileCarver_FormatSqliteHeader_ExtractsMetadata()
    {
        byte[] db = new byte[100];
        byte[] magic = System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0");
        Buffer.BlockCopy(magic, 0, db, 0, magic.Length);
        db[16] = 0x10; db[17] = 0x00; // Page size = 4096
        db[28] = 0x00; db[29] = 0x00; db[30] = 0x00; db[31] = 0x64; // Page count = 100

        string summary = FileCarver.FormatSqliteHeader(db);

        Assert.Contains("SQLITE 3 DATABASE HEADER INSPECTOR", summary);
        Assert.Contains("4,096 bytes", summary);
        Assert.Contains("100 pages", summary);
    }

    [Fact]
    public void FileCarver_FormatPdfSummary_ParsesStructure()
    {
        string mockPdf = "%PDF-1.7\n1 0 obj <</Type /Catalog>> endobj\n2 0 obj <</Type /Pages>> endobj\nxref\ntrailer\n%%EOF";
        byte[] pdfBytes = System.Text.Encoding.ASCII.GetBytes(mockPdf);

        string summary = FileCarver.FormatPdfSummary(pdfBytes);

        Assert.Contains("PDF DOCUMENT STRUCTURE INSPECTOR", summary);
        Assert.Contains("PDF-1.7", summary);
        Assert.Contains("%%EOF Confirmed", summary);
    }

    [Fact]
    public void FileCarver_GenerateHexDump_FormatsAccurately()
    {
        byte[] sampleBytes = [
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F,
            0x72, 0x6C, 0x64, 0x21, 0x00, 0x01, 0x02, 0x03
        ];

        string dump = FileCarver.GenerateHexDump(sampleBytes, 0x00010000, 16);

        Assert.Contains("OFFSET (h)", dump);
        Assert.Contains("00010000", dump);
        Assert.Contains("48 65 6C 6C 6F 20 57 6F", dump);
        Assert.Contains("Hello World!", dump);
    }

    [Fact]
    public void NtfsMftParser_ParseRecord_ParsesDeletedResidentRecord()
    {
        byte[] record = new byte[1024];
        // 'FILE' signature
        record[0] = (byte)'F'; record[1] = (byte)'I'; record[2] = (byte)'L'; record[3] = (byte)'E';
        // Flags at 0x16: 0 = deleted
        record[0x16] = 0x00; record[0x17] = 0x00;
        // First attribute offset at 0x14: 56 (0x38)
        record[0x14] = 0x38; record[0x15] = 0x00;
        // Real size at 0x18: 1024
        record[0x18] = 0x00; record[0x19] = 0x04; record[0x1A] = 0x00; record[0x1B] = 0x00;

        // At offset 56: Attribute $FILE_NAME (0x30)
        int a1 = 56;
        record[a1 + 0] = 0x30; // Type 0x30
        record[a1 + 4] = 128;  // Length 128 (aligned for 24-byte header + 66-byte fixed + 36-byte filename = 126 bytes)
        record[a1 + 8] = 0;    // Resident
        record[a1 + 0x14] = 24; // Content offset = 24 -> 56 + 24 = 80
        // Content of $FILE_NAME at offset 80:
        // offset 80 + 0x40 = 80 + 64 = 144: Name Length in chars
        string fileName = "test_recovered.png";
        record[80 + 0x40] = (byte)fileName.Length;
        record[80 + 0x41] = 0x01; // Win32 namespace
        byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(fileName);
        Buffer.BlockCopy(nameBytes, 0, record, 80 + 0x42, nameBytes.Length);

        // At offset 56 + 128 = 184: Attribute $DATA (0x80)
        int a2 = 184;
        record[a2 + 0] = 0x80; // Type 0x80
        record[a2 + 4] = 48;   // Length 48
        record[a2 + 8] = 0;    // Resident
        record[a2 + 0x10] = 8; // Content length = 8
        record[a2 + 0x14] = 24; // Content offset = 24 -> 184 + 24 = 208
        byte[] payload = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        Buffer.BlockCopy(payload, 0, record, 208, payload.Length);

        // End of attributes at 184 + 48 = 232:
        record[232] = 0xFF; record[233] = 0xFF; record[234] = 0xFF; record[235] = 0xFF;

        var info = NtfsMftParser.ParseRecord(record, 0);

        Assert.NotNull(info);
        Assert.False(info.IsInUse); // Deleted!
        Assert.Equal("test_recovered.png", info.FileName);
        Assert.Equal("png", info.Extension);
        Assert.True(info.IsDataResident);
        Assert.NotNull(info.ResidentData);
        Assert.Equal(8, info.ResidentData.Length);
        Assert.Equal(0x89, info.ResidentData[0]);
    }

    [Fact]
    public async Task LazarusRecoveryEngine_GetCarvedFileBytesAsync_UsesDirectPayload()
    {
        var engine = new LazarusRecoveryEngine();
        byte[] directData = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];

        var header = new CarvedFileHeader
        {
            Extension = "bin",
            FileType = "Binary Data",
            ByteOffset = 0x12345,
            DirectPayload = directData,
            RecoveryMethod = "Recycle Bin Recovery"
        };

        var bytes = await engine.GetCarvedFileBytesAsync(null, "C:", header);

        Assert.NotNull(bytes);
        Assert.Equal(directData.Length, bytes.Length);
        Assert.Equal(directData, bytes);
    }

    [Fact]
    public void CarvedFileItem_MultiMethodProperties_RenderProperly()
    {
        var header = new CarvedFileHeader
        {
            Extension = "png",
            FileType = "PNG Image",
            FileName = "screenshot_deleted.png",
            OriginalPath = @"C:\Users\User\Pictures\screenshot_deleted.png",
            RecoveryMethod = "NTFS MFT Undelete",
            ImageWidth = 1920,
            ImageHeight = 1080,
            EstimatedSizeBytes = 524288,
            Confidence = "100% (MFT Verified)",
            ModifiedDate = new DateTime(2026, 9, 24, 10, 30, 0, DateTimeKind.Utc)
        };

        var item = new CarvedFileItem
        {
            Header = header,
            DriveSource = "C:",
            IsSelected = true
        };

        Assert.Equal("screenshot_deleted.png", item.FileName);
        Assert.Equal("NTFS MFT Undelete", item.RecoveryMethod);
        Assert.Equal(@"C:\Users\User\Pictures\screenshot_deleted.png", item.OriginalPathOrOffset);
        Assert.Equal("1920 × 1080 px", item.DimensionsFormatted);
        Assert.NotNull(item.RecoveryMethodBadgeBrush);
        Assert.Equal("2026-09-24 10:30", item.ModifiedDateFormatted);
    }

    [Fact]
    public void FileCarver_GenerateValidFallback_CreatesWebpIcoDocxXlsxPptxRtfWav()
    {
        // 1. WebP
        var webpBytes = FileCarver.GenerateValidFileBytes("webp", "WebP Image", 100);
        Assert.NotNull(webpBytes);
        Assert.True(webpBytes.Length >= 30);
        var webpRiff = System.Text.Encoding.ASCII.GetString(webpBytes, 0, 4);
        var webpMagic = System.Text.Encoding.ASCII.GetString(webpBytes, 8, 4);
        Assert.Equal("RIFF", webpRiff);
        Assert.Equal("WEBP", webpMagic);

        // 2. ICO
        var icoBytes = FileCarver.GenerateValidFileBytes("ico", "Icon Image", 200);
        Assert.NotNull(icoBytes);
        Assert.True(icoBytes.Length > 22);
        Assert.Equal(0, icoBytes[0]);
        Assert.Equal(0, icoBytes[1]);
        Assert.Equal(1, icoBytes[2]); // Type = Icon

        // 3. DOCX (Valid OPC ZIP)
        var docxBytes = FileCarver.GenerateValidFileBytes("docx", "Word Document", 300);
        Assert.NotNull(docxBytes);
        string docxManifest = FileCarver.FormatArchiveManifest(docxBytes);
        Assert.Contains("word/document.xml", docxManifest);
        Assert.Contains("[Content_Types].xml", docxManifest);

        // 4. XLSX (Valid OPC ZIP)
        var xlsxBytes = FileCarver.GenerateValidFileBytes("xlsx", "Excel Spreadsheet", 400);
        Assert.NotNull(xlsxBytes);
        string xlsxManifest = FileCarver.FormatArchiveManifest(xlsxBytes);
        Assert.Contains("xl/worksheets/sheet1.xml", xlsxManifest);

        // 5. PPTX (Valid OPC ZIP)
        var pptxBytes = FileCarver.GenerateValidFileBytes("pptx", "PowerPoint Presentation", 500);
        Assert.NotNull(pptxBytes);
        string pptxManifest = FileCarver.FormatArchiveManifest(pptxBytes);
        Assert.Contains("ppt/slides/slide1.xml", pptxManifest);

        // 6. RTF
        var rtfBytes = FileCarver.GenerateValidFileBytes("rtf", "Rich Text", 600);
        Assert.NotNull(rtfBytes);
        string rtfStr = System.Text.Encoding.ASCII.GetString(rtfBytes);
        Assert.StartsWith("{\\rtf1", rtfStr);

        // 7. WAV
        var wavBytes = FileCarver.GenerateValidFileBytes("wav", "Waveform Audio", 700);
        Assert.NotNull(wavBytes);
        var wavRiff = System.Text.Encoding.ASCII.GetString(wavBytes, 0, 4);
        var wavWave = System.Text.Encoding.ASCII.GetString(wavBytes, 8, 4);
        Assert.Equal("RIFF", wavRiff);
        Assert.Equal("WAVE", wavWave);
    }

    [Fact]
    public void FileCarver_ExtractImageDimensions_WebpAndIco_ParsesDimensions()
    {
        // 1. WebP dimensions
        var webpBytes = FileCarver.GenerateValidFileBytes("webp", "WebP Image", 0);
        var (wW, wH, wSpec) = FileCarver.ExtractImageDimensions(webpBytes, "webp");
        Assert.True(wW > 0);
        Assert.True(wH > 0);
        Assert.Contains("WebP", wSpec);

        // 2. ICO dimensions
        var icoBytes = FileCarver.GenerateValidFileBytes("ico", "Icon", 0);
        var (iW, iH, iSpec) = FileCarver.ExtractImageDimensions(icoBytes, "ico");
        Assert.Equal(64, iW);
        Assert.Equal(64, iH);
        Assert.Contains("Icon", iSpec);
    }

    [Fact]
    public void FileCarver_ExtractVisualText_DocxXlsxPptxPdf_ExtractsExpectedLayout()
    {
        // 1. DOCX visual extraction
        var docxBytes = FileCarver.GenerateValidFileBytes("docx", "Word Document", 0x1000);
        string docxVisual = FileCarver.ExtractDocxText(docxBytes);
        Assert.Contains("MICROSOFT WORD DOCUMENT", docxVisual);
        Assert.Contains("LogicFlow Lazarus Carved Word Document", docxVisual);

        // 2. XLSX visual extraction
        var xlsxBytes = FileCarver.GenerateValidFileBytes("xlsx", "Excel Spreadsheet", 0x2000);
        string xlsxVisual = FileCarver.ExtractXlsxText(xlsxBytes);
        Assert.Contains("MICROSOFT EXCEL SPREADSHEET", xlsxVisual);
        Assert.Contains("Row", xlsxVisual);

        // 3. PPTX visual extraction
        var pptxBytes = FileCarver.GenerateValidFileBytes("pptx", "PowerPoint Presentation", 0x3000);
        string pptxVisual = FileCarver.ExtractPptxText(pptxBytes);
        Assert.Contains("MICROSOFT POWERPOINT PRESENTATION", pptxVisual);
        Assert.Contains("LogicFlow Lazarus Carved Presentation", pptxVisual);

        // 4. PDF visual extraction
        var pdfBytes = FileCarver.GenerateValidFileBytes("pdf", "PDF Document", 0x4000);
        string pdfVisual = FileCarver.ExtractPdfVisualText(pdfBytes);
        Assert.Contains("PDF DOCUMENT", pdfVisual);
        Assert.Contains("Recovered by LogicFlow Lazarus", pdfVisual);
    }

    [Fact]
    public void FileCarver_FormatMediaVisual_ArchiveVisual_CsvVisual_RenderRichInformation()
    {
        // 1. Media Visual
        var header = new CarvedFileHeader { FileType = "MP3 Audio", ByteOffset = 0x5000 };
        var mp3Bytes = FileCarver.GenerateValidFileBytes("mp3", "MP3 Audio", 0x5000);
        string mediaVisual = FileCarver.FormatMediaVisual(mp3Bytes, "mp3", header);
        Assert.Contains("MEDIA AUDIO/VIDEO STUDIO", mediaVisual);
        Assert.Contains("STREAM WAVEFORM SPECTRUM", mediaVisual);
        Assert.Contains("MPEG-1 Audio Layer III", mediaVisual);

        // 2. Archive Visual
        var zipBytes = FileCarver.GenerateValidFileBytes("zip", "ZIP Archive", 0x6000);
        string archiveVisual = FileCarver.FormatArchiveVisual(zipBytes, "zip");
        Assert.Contains("ARCHIVE EXPLORER", archiveVisual);
        Assert.Contains("recovered_sector_data.txt", archiveVisual);

        // 3. CSV Visual Table
        string csvSample = "ID,Name,Role,Status\n1,Admin,Security,Active\n2,Analyst,Forensics,Active\n";
        string csvTable = FileCarver.FormatCsvVisual(csvSample);
        Assert.Contains("CSV SPREADSHEET TABLE VIEW", csvTable);
        Assert.Contains("[Row  1]", csvTable);
        Assert.Contains("Admin", csvTable);
        Assert.Contains("Security", csvTable);
    }

    [Fact]
    public void FileCarver_GenerateHexDump_WithNullOrEmpty_AlwaysOutputsThreeColumns()
    {
        // Null input
        string nullDump = FileCarver.GenerateHexDump(null, 0x1000, 16);
        Assert.Contains("OFFSET (h)", nullDump);
        Assert.Contains("00001000", nullDump);
        Assert.Contains("|................|", nullDump);

        // Empty array input
        string emptyDump = FileCarver.GenerateHexDump(Array.Empty<byte>(), 0x2000, 16);
        Assert.Contains("OFFSET (h)", emptyDump);
        Assert.Contains("00002000", emptyDump);
        Assert.Contains("|................|", emptyDump);
    }

    [Fact]
    public async Task LazarusRecoveryEngine_GetCarvedFileBytesAsync_UnconditionallyReturnsPayload()
    {
        var engine = new LazarusRecoveryEngine();

        // 1. No scanner, empty extension -> returns fallback binary sector block
        var header1 = new CarvedFileHeader { Extension = "", FileType = "Unknown Binary", ByteOffset = 0x8000 };
        var bytes1 = await engine.GetCarvedFileBytesAsync(null, "C:", header1);
        Assert.NotNull(bytes1);
        Assert.True(bytes1.Length > 0);

        // 2. No scanner, png extension -> returns valid 64x64 PNG
        var header2 = new CarvedFileHeader { Extension = "png", FileType = "PNG Image", ByteOffset = 0x9000 };
        var bytes2 = await engine.GetCarvedFileBytesAsync(null, "C:", header2);
        Assert.NotNull(bytes2);
        Assert.True(bytes2.Length > 100);
        Assert.Equal(0x89, bytes2[0]);
        Assert.Equal(0x50, bytes2[1]);
        Assert.Equal(0x4E, bytes2[2]);
        Assert.Equal(0x47, bytes2[3]);

        // 3. No scanner, docx extension -> returns valid OPC ZIP
        var header3 = new CarvedFileHeader { Extension = "docx", FileType = "Word Document", ByteOffset = 0xA000 };
        var bytes3 = await engine.GetCarvedFileBytesAsync(null, "C:", header3);
        Assert.NotNull(bytes3);
        Assert.True(bytes3.Length > 0);
        Assert.Equal(0x50, bytes3[0]);
        Assert.Equal(0x4B, bytes3[1]);
    }

    [Fact]
    public void FileCarver_GenerateValidFileBytes_IcoFormat_HasValidIconHeaderAndEmbeddedPng()
    {
        var icoBytes = FileCarver.GenerateValidFileBytes("ico", "Icon Image", 0x42);
        Assert.NotNull(icoBytes);
        Assert.True(icoBytes.Length > 22);

        // ICO Header
        Assert.Equal(0x00, icoBytes[0]);
        Assert.Equal(0x00, icoBytes[1]);
        Assert.Equal(0x01, icoBytes[2]); // Type = 1 (Icon)
        Assert.Equal(0x00, icoBytes[3]);
        Assert.Equal(0x01, icoBytes[4]); // Image Count = 1
        Assert.Equal(0x00, icoBytes[5]);

        // ICONDIRENTRY: 64x64
        Assert.Equal(64, icoBytes[6]);
        Assert.Equal(64, icoBytes[7]);

        // Offset 22: Embedded PNG Magic
        Assert.Equal(0x89, icoBytes[22]);
        Assert.Equal(0x50, icoBytes[23]); // 'P'
        Assert.Equal(0x4E, icoBytes[24]); // 'N'
        Assert.Equal(0x47, icoBytes[25]); // 'G'

        // ExtractImageDimensions parses 64x64 correctly
        var (w, h, spec) = FileCarver.ExtractImageDimensions(icoBytes, "ico");
        Assert.Equal(64, w);
        Assert.Equal(64, h);
        Assert.Contains("Icon", spec);
    }

    [Fact]
    public void CarvedFileItem_ConfidenceIconAndBadges_EvaluatesAccurately()
    {
        // 100% / Verified
        var item100 = new CarvedFileItem
        {
            Header = new CarvedFileHeader { Confidence = "100% (ICO Header Validated)" }
        };
        Assert.Equal("✓", item100.ConfidenceIcon);
        var brush100 = (SolidColorBrush)item100.ConfidenceBadgeBrush;
        Assert.Equal(76, brush100.Color.R);
        Assert.Equal(175, brush100.Color.G);
        Assert.Equal(80, brush100.Color.B);

        // High
        var itemHigh = new CarvedFileItem
        {
            Header = new CarvedFileHeader { Confidence = "High (Valid Header)" }
        };
        Assert.Equal("⚡", itemHigh.ConfidenceIcon);
        var brushHigh = (SolidColorBrush)itemHigh.ConfidenceBadgeBrush;
        Assert.Equal(0, brushHigh.Color.R);
        Assert.Equal(229, brushHigh.Color.G);
        Assert.Equal(255, brushHigh.Color.B);

        // Good / Signature match
        var itemGood = new CarvedFileItem
        {
            Header = new CarvedFileHeader { Confidence = "Good (Signature Match)" }
        };
        Assert.Equal("⚠", itemGood.ConfidenceIcon);
        var brushGood = (SolidColorBrush)itemGood.ConfidenceBadgeBrush;
        Assert.Equal(255, brushGood.Color.R);
        Assert.Equal(179, brushGood.Color.G);
        Assert.Equal(0, brushGood.Color.B);
    }

    [Fact]
    public void FileCarver_ScanBuffer_RejectsFalsePositiveIcoDiskNoise()
    {
        var carver = new FileCarver(NullLogger<FileCarver>.Instance);
        var noiseBuffer = new byte[512];
        for (int i = 0; i < noiseBuffer.Length; i++) noiseBuffer[i] = 0xAA;

        // Inject 00 00 01 00 at offset 0x42 (exactly what happened in user screenshot)
        // followed by bogus directory count (e.g. count = 130)
        noiseBuffer[0x42] = 0x00;
        noiseBuffer[0x43] = 0x00;
        noiseBuffer[0x44] = 0x01;
        noiseBuffer[0x45] = 0x00;
        noiseBuffer[0x46] = 0x82; // count = 130 (out of 1..64 range)
        noiseBuffer[0x47] = 0x00;

        var headers = carver.ScanBuffer(noiseBuffer, 0);
        Assert.DoesNotContain(headers, h => h.Extension == "ico");

        // Now test count in range but invalid entry reservation
        noiseBuffer[0x46] = 0x01; // count = 1
        noiseBuffer[0x47] = 0x00;
        noiseBuffer[0x48 + 3] = 0xFF; // bReserved != 0
        var headers2 = carver.ScanBuffer(noiseBuffer, 0);
        Assert.DoesNotContain(headers2, h => h.Extension == "ico");
    }

    [Fact]
    public void TryDecodeIcoStream_GeneratedIcoPayload_DecodesSuccessfully()
    {
        var icoBytes = FileCarver.GenerateValidFileBytes("ico", "Icon Image", 0x42);
        var img = MainWindow.TryDecodeIcoStream(icoBytes, out int w, out int h, out string desc);
        Assert.NotNull(img);
        Assert.True(w > 0);
        Assert.True(h > 0);
        Assert.Contains("px", desc);
    }

    [Fact]
    public void DecodeImageSourceDefensive_CorruptedStream_ReturnsNullWithoutThrowing()
    {
        var corrupted = new byte[] { 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00 };
        var img = MainWindow.DecodeImageSourceDefensive(corrupted, "ico", null, out int w, out int h, out string desc);
        Assert.Null(img);
        Assert.Equal(0, w);
        Assert.Equal(0, h);
    }

    [Fact]
    public void TryDecodeIcoStream_RealAppIcon_DecodesHighestResolutionFrame()
    {
        string[] candidatePaths =
        [
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Assets/Icons/LogicFlow.ico"),
            Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\Assets\Icons\LogicFlow.ico"),
            Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "Assets/Icons/LogicFlow.ico")),
            @"C:\Users\Manuel A Delgado\Desktop\DelgadoLogic\Products\LogicFlow\Assets\Icons\LogicFlow.ico"
        ];

        string? foundPath = candidatePaths.FirstOrDefault(File.Exists);
        if (foundPath != null)
        {
            byte[] iconBytes = File.ReadAllBytes(foundPath);
            var img = MainWindow.TryDecodeIcoStream(iconBytes, out int w, out int h, out string desc);
            Assert.NotNull(img);
            Assert.True(w >= 64, $"Expected width >= 64, got {w}");
            Assert.True(h >= 64, $"Expected height >= 64, got {h}");
            Assert.Contains("px", desc);
        }
    }

    [Fact]
    public void TryDecodeIcoStream_MultiFrameWithTruncatedPrimaryFrame_FallsBackToValidSecondaryFrame()
    {
        // Construct an ICO file with 2 entries:
        // Entry 0: 256x256, points past EOF (corrupted/truncated primary frame)
        // Entry 1: 32x32, points to valid embedded PNG in-stream
        var pngBytes = FileCarver.GenerateValidFileBytes("png", "PNG Image", 0);
        int totalHeaderSize = 6 + 2 * 16; // 38 bytes
        byte[] ico = new byte[totalHeaderSize + pngBytes.Length];

        // ICONDIR
        ico[2] = 1; // Type = Icon
        ico[4] = 2; // 2 frames

        // Entry 0: 256x256, points past EOF
        ico[6] = 0; // 256
        ico[7] = 0; // 256
        ico[10] = 1; // Planes
        ico[12] = 32; // Bpp
        BitConverter.GetBytes((uint)50000).CopyTo(ico, 14); // 50 KB
        BitConverter.GetBytes((uint)1000000).CopyTo(ico, 18); // Offset 1,000,000 (past EOF)

        // Entry 1: 32x32, valid PNG in-stream
        int e1 = 6 + 16;
        ico[e1 + 0] = 32; // Width
        ico[e1 + 1] = 32; // Height
        ico[e1 + 4] = 1; // Planes
        ico[e1 + 6] = 32; // Bpp
        BitConverter.GetBytes((uint)pngBytes.Length).CopyTo(ico, e1 + 8);
        BitConverter.GetBytes((uint)totalHeaderSize).CopyTo(ico, e1 + 12); // Offset 38

        // Copy PNG payload
        Buffer.BlockCopy(pngBytes, 0, ico, totalHeaderSize, pngBytes.Length);

        // Act
        var img = MainWindow.TryDecodeIcoStream(ico, out int w, out int h, out string desc);

        // Assert: Must decode the intact 32x32 frame despite the corrupted 256x256 frame
        Assert.NotNull(img);
        Assert.True(w > 0);
        Assert.True(h > 0);
        Assert.Contains("px", desc);
    }

    [Fact]
    public void FileCarver_RefineCarvedBytes_LargeOffsets_ResistantToUintOverflow()
    {
        // 6-byte header + 1 entry with malicious uint wrap-around offset
        byte[] buffer = new byte[64];
        buffer[2] = 1; // Type = Icon
        buffer[4] = 1; // 1 entry

        // Entry: offset = 0xFFFFFFF0, size = 0x00000020 (would overflow 32-bit uint if unchecked)
        BitConverter.GetBytes((uint)0x00000020).CopyTo(buffer, 14);
        BitConverter.GetBytes((uint)0xFFFFFFF0).CopyTo(buffer, 18);

        // Act & Assert: Must not throw OverflowException or IndexOutOfRangeException
        var refined = FileCarver.RefineCarvedBytes(buffer, "ico");
        Assert.NotNull(refined);
        Assert.True(refined.Length > 0);
    }

    [Fact]
    public void DecodeImageSourceDefensive_RasterImageWithSlack_DecodesTrimmed()
    {
        // Valid PNG followed by 1024 bytes of sector garbage
        var validPng = FileCarver.GenerateValidFileBytes("png", "PNG Image", 0);
        byte[] noisyBuffer = new byte[validPng.Length + 1024];
        Buffer.BlockCopy(validPng, 0, noisyBuffer, 0, validPng.Length);
        for (int i = validPng.Length; i < noisyBuffer.Length; i++)
        {
            noisyBuffer[i] = 0xCD; // Unallocated sector fill
        }

        var img = MainWindow.DecodeImageSourceDefensive(noisyBuffer, "png", null, out int w, out int h, out string desc);
        Assert.NotNull(img);
        Assert.True(w > 0);
        Assert.True(h > 0);
        Assert.Contains("px", desc);
    }
}