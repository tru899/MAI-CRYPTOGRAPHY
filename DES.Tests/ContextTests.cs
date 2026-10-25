using System.Text;

namespace DES.Tests;

public class ContextTests
{
    private static readonly byte[] DES_KEY = Convert.FromHexString("133457799BBCDFF1");
    private static readonly byte[] DES_IV = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] DEAL_KEY = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    private static readonly byte[] DEAL_IV = Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");
    private const long DELTA = 12345;

    private static SymmetricCipher NewDes(EncryptionMode mode, PaddingMode padding) =>
        new(DES_KEY, mode, padding, new Des(), DES_IV, DELTA);

    private static SymmetricCipher NewDeal(EncryptionMode mode, PaddingMode padding) =>
        new(DEAL_KEY, mode, padding, new Deal(), DEAL_IV, DELTA);

    private static byte[] Payload(int length, int seed)
    {
        byte[] data = new byte[length];
        new Random(seed).NextBytes(data);
        for (int i = 0; i < length; i++) if (data[i] == 0) data[i] = 1;
        return data;
    }

    public static TheoryData<EncryptionMode, PaddingMode> AllModes()
    {
        TheoryData<EncryptionMode, PaddingMode> data = new();
        foreach (EncryptionMode mode in Enum.GetValues<EncryptionMode>())
        foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
            data.Add(mode, padding);
        return data;
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public void Des_RoundTrip(EncryptionMode mode, PaddingMode padding)
    {
        foreach (int length in new[] { 0, 1, 7, 8, 9, 64, 100 })
        {
            byte[] plain = Payload(length, length);
            SymmetricCipher cipher = NewDes(mode, padding);

            Assert.Equal(plain, cipher.Decrypt(cipher.Encrypt(plain)));
        }
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public void Deal_RoundTrip(EncryptionMode mode, PaddingMode padding)
    {
        foreach (int length in new[] { 0, 1, 15, 16, 17, 100 })
        {
            byte[] plain = Payload(length, length);
            SymmetricCipher cipher = NewDeal(mode, padding);

            Assert.Equal(plain, cipher.Decrypt(cipher.Encrypt(plain)));
        }
    }

    [Fact]
    public async Task Async_RoundTrip()
    {
        byte[] plain = Payload(1000, 3);
        SymmetricCipher cipher = NewDes(EncryptionMode.CBC, PaddingMode.PKCS7);

        byte[] encrypted = await cipher.EncryptAsync(plain);

        Assert.Equal(plain, await cipher.DecryptAsync(encrypted));
    }

    public static TheoryData<EncryptionMode, string> ZerosCases()
    {
        TheoryData<EncryptionMode, string> data = new();
        foreach (EncryptionMode mode in Enum.GetValues<EncryptionMode>())
            foreach (string text in new[] { "0", " ", "0000", "    ", "abc   ", "0 0 0", "12345678" })
                data.Add(mode, text);
        return data;
    }

    [Theory]
    [MemberData(nameof(ZerosCases))]
    public void Zeros_TextWithZeroCharAndSpaces_Survives(EncryptionMode mode, string text)
    {
        byte[] plain = Encoding.UTF8.GetBytes(text);

        SymmetricCipher des = NewDes(mode, PaddingMode.ZEROS);
        Assert.Equal(text, Encoding.UTF8.GetString(des.Decrypt(des.Encrypt(plain))));

        SymmetricCipher deal = NewDeal(mode, PaddingMode.ZEROS);
        Assert.Equal(text, Encoding.UTF8.GetString(deal.Decrypt(deal.Encrypt(plain))));
    }

    [Theory]
    [InlineData(EncryptionMode.ECB)]
    [InlineData(EncryptionMode.CBC)]
    [InlineData(EncryptionMode.PCBC)]
    public void Zeros_SingleZeroByte_Survives(EncryptionMode mode)
    {
        SymmetricCipher des = NewDes(mode, PaddingMode.ZEROS);
        Assert.Equal([0x00], des.Decrypt(des.Encrypt([0x00])));

        SymmetricCipher deal = NewDeal(mode, PaddingMode.ZEROS);
        Assert.Equal([0x00], deal.Decrypt(deal.Encrypt([0x00])));
    }

    [Theory]
    [InlineData(EncryptionMode.ECB)]
    [InlineData(EncryptionMode.CBC)]
    [InlineData(EncryptionMode.PCBC)]
    public void Zeros_TrailingZeroAfterData_IsAmbiguous(EncryptionMode mode)
    {
        SymmetricCipher cipher = NewDes(mode, PaddingMode.ZEROS);

        Assert.Equal(cipher.Encrypt([0x41]), cipher.Encrypt([0x41, 0x00]));
        Assert.Equal([0x41], cipher.Decrypt(cipher.Encrypt([0x41, 0x00])));
    }

    [Theory]
    [InlineData(EncryptionMode.CFB)]
    [InlineData(EncryptionMode.OFB)]
    [InlineData(EncryptionMode.CTR)]
    [InlineData(EncryptionMode.RD)]
    public void Zeros_TrailingZeroByte_Survives_InStreamModes(EncryptionMode mode)
    {
        SymmetricCipher cipher = NewDes(mode, PaddingMode.ZEROS);

        Assert.Equal([0x41, 0x00], cipher.Decrypt(cipher.Encrypt([0x41, 0x00])));
        Assert.Equal([0x00], cipher.Decrypt(cipher.Encrypt([0x00])));
    }

    [Theory]
    [InlineData(PaddingMode.ANSIX923)]
    [InlineData(PaddingMode.PKCS7)]
    [InlineData(PaddingMode.ISO10126)]
    public void CounterPaddings_KeepZeroBytes(PaddingMode padding)
    {
        byte[] plain = [0x00, 0x41, 0x00, 0x00];
        SymmetricCipher cipher = NewDes(EncryptionMode.CBC, padding);

        Assert.Equal(plain, cipher.Decrypt(cipher.Encrypt(plain)));
    }

    [Theory]
    [InlineData(PaddingMode.ZEROS, 8)]
    [InlineData(PaddingMode.ANSIX923, 16)]
    [InlineData(PaddingMode.PKCS7, 16)]
    [InlineData(PaddingMode.ISO10126, 16)]
    public void FullBlock_PaddingLength(PaddingMode padding, int expected)
    {
        SymmetricCipher cipher = NewDes(EncryptionMode.ECB, padding);

        Assert.Equal(expected, cipher.Encrypt(Payload(8, 1)).Length);
    }

    [Fact]
    public void Ecb_LeaksRepeatedBlocks()
    {
        byte[] plain = Enumerable.Repeat((byte)0xAB, 32).ToArray();

        byte[] ecb = NewDes(EncryptionMode.ECB, PaddingMode.PKCS7).Encrypt(plain);
        byte[] cbc = NewDes(EncryptionMode.CBC, PaddingMode.PKCS7).Encrypt(plain);

        Assert.Equal(ecb[0..8], ecb[8..16]);
        Assert.NotEqual(cbc[0..8], cbc[8..16]);
    }

    [Theory]
    [InlineData(EncryptionMode.CFB)]
    [InlineData(EncryptionMode.OFB)]
    [InlineData(EncryptionMode.CTR)]
    [InlineData(EncryptionMode.RD)]
    public void StreamModes_KeepLength(EncryptionMode mode)
    {
        Assert.Equal(13, NewDes(mode, PaddingMode.PKCS7).Encrypt(Payload(13, 1)).Length);
    }

    [Fact]
    public void Rd_EvenDelta_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipher(DES_KEY, EncryptionMode.RD, PaddingMode.PKCS7, new Des(), DES_IV, 4L));
    }

    [Fact]
    public void Cbc_WithoutIv_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipher(DES_KEY, EncryptionMode.CBC, PaddingMode.PKCS7, new Des()));
    }

    [Fact]
    public void WrongIvLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipher(DES_KEY, EncryptionMode.CBC, PaddingMode.PKCS7, new Des(), new byte[4]));
    }

    [Theory]
    [InlineData(EncryptionMode.ECB)]
    [InlineData(EncryptionMode.CBC)]
    [InlineData(EncryptionMode.PCBC)]
    [InlineData(EncryptionMode.CFB)]
    [InlineData(EncryptionMode.OFB)]
    [InlineData(EncryptionMode.CTR)]
    [InlineData(EncryptionMode.RD)]
    public async Task File_RoundTrip_AcrossChunks(EncryptionMode mode)
    {
        byte[] plain = Payload(2 * 8 * 65536 + 13, 7);
        string dir = Directory.CreateTempSubdirectory().FullName;

        try
        {
            string source = Path.Combine(dir, "in"), encrypted = Path.Combine(dir, "enc"), restored = Path.Combine(dir, "out");
            await File.WriteAllBytesAsync(source, plain);
            SymmetricCipher cipher = NewDes(mode, PaddingMode.PKCS7);

            await cipher.EncryptAsync(source, encrypted);
            await cipher.DecryptAsync(encrypted, restored);

            Assert.Equal(plain, await File.ReadAllBytesAsync(restored));
            Assert.Equal(cipher.Encrypt(plain), await File.ReadAllBytesAsync(encrypted));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task File_Deal_RoundTrip()
    {
        byte[] plain = Payload(5000, 9);
        string dir = Directory.CreateTempSubdirectory().FullName;

        try
        {
            string source = Path.Combine(dir, "in"), encrypted = Path.Combine(dir, "enc"), restored = Path.Combine(dir, "out");
            await File.WriteAllBytesAsync(source, plain);
            SymmetricCipher cipher = NewDeal(EncryptionMode.CBC, PaddingMode.PKCS7);

            await cipher.EncryptAsync(source, encrypted);
            await cipher.DecryptAsync(encrypted, restored);

            Assert.Equal(plain, await File.ReadAllBytesAsync(restored));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task File_Empty()
    {
        string dir = Directory.CreateTempSubdirectory().FullName;

        try
        {
            string source = Path.Combine(dir, "in"), encrypted = Path.Combine(dir, "enc"), restored = Path.Combine(dir, "out");
            await File.WriteAllBytesAsync(source, []);
            SymmetricCipher cipher = NewDes(EncryptionMode.CBC, PaddingMode.PKCS7);

            await cipher.EncryptAsync(source, encrypted);
            await cipher.DecryptAsync(encrypted, restored);

            Assert.Equal(8, new FileInfo(encrypted).Length);
            Assert.Empty(await File.ReadAllBytesAsync(restored));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
