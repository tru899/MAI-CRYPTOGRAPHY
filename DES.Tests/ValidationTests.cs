namespace DES.Tests;

public class ValidationTests
{
    private static readonly byte[] DES_KEY = Convert.FromHexString("133457799BBCDFF1");
    private static readonly byte[] DES_IV = Convert.FromHexString("0123456789ABCDEF");

    [Fact]
    public void Permute_NullArguments()
    {
        Bits bits = new Bits();
        Assert.Throws<ArgumentNullException>(() => bits.Permute(null!, [1], BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB));
        Assert.Throws<ArgumentNullException>(() => bits.Permute([1], null!, BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB));
    }

    [Fact]
    public void Permute_EmptyTable()
    {
        Assert.Throws<ArgumentException>(() => new Bits().Permute([1], [], BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-8)]
    [InlineData(7)]
    public void Feistel_BadBlockSize(int block_size)
    {
        Assert.Throws<ArgumentException>(() => new FeistelNetwork(new DesKeyExpansion(), new DesRoundFunction(), block_size));
    }

    [Fact]
    public void Feistel_NullParts()
    {
        Assert.Throws<ArgumentNullException>(() => new FeistelNetwork(null!, new DesRoundFunction(), 8));
        Assert.Throws<ArgumentNullException>(() => new FeistelNetwork(new DesKeyExpansion(), null!, 8));
    }

    [Fact]
    public void Des_EncryptBeforeSetKey()
    {
        Assert.Throws<InvalidOperationException>(() => new Des().Encrypt(DES_IV));
        Assert.Throws<InvalidOperationException>(() => new Des().Decrypt(DES_IV));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(16)]
    public void Des_WrongKeyLength(int length)
    {
        Assert.Throws<ArgumentException>(() => new Des().SetKey(new byte[length]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    public void Des_WrongBlockLength(int length)
    {
        Des des = new Des();
        des.SetKey(DES_KEY);

        Assert.Throws<ArgumentException>(() => des.Encrypt(new byte[length]));
        Assert.Throws<ArgumentException>(() => des.Decrypt(new byte[length]));
    }

    [Fact]
    public void Des_Nulls()
    {
        Des des = new Des();
        Assert.Throws<ArgumentNullException>(() => des.SetKey(null!));
        des.SetKey(DES_KEY);
        Assert.Throws<ArgumentNullException>(() => des.Encrypt(null!));
    }

    [Fact]
    public void DesRoundFunction_WrongSizes()
    {
        DesRoundFunction f = new DesRoundFunction();
        Assert.Throws<ArgumentException>(() => f.Transform(new byte[5], new byte[6]));
        Assert.Throws<ArgumentException>(() => f.Transform(new byte[4], new byte[7]));
    }

    [Fact]
    public void Deal_EncryptBeforeSetKey()
    {
        Assert.Throws<InvalidOperationException>(() => new Deal().Encrypt(new byte[16]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(20)]
    [InlineData(33)]
    public void Deal_WrongKeyLength(int length)
    {
        Assert.Throws<ArgumentException>(() => new Deal().SetKey(new byte[length]));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(17)]
    public void Deal_WrongBlockLength(int length)
    {
        Deal deal = new Deal();
        deal.SetKey(new byte[16]);

        Assert.Throws<ArgumentException>(() => deal.Encrypt(new byte[length]));
    }

    [Fact]
    public void Context_NullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new SymmetricCipher(null!, EncryptionMode.ECB, PaddingMode.PKCS7, new Des()));
        Assert.Throws<ArgumentNullException>(() => new SymmetricCipher(DES_KEY, EncryptionMode.ECB, PaddingMode.PKCS7, null!));

        SymmetricCipher cipher = new SymmetricCipher(DES_KEY, EncryptionMode.ECB, PaddingMode.PKCS7, new Des());
        Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null!));
        Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(null!));
    }

    [Fact]
    public void Context_UnknownEnums()
    {
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, (EncryptionMode)99, PaddingMode.PKCS7, new Des(), DES_IV));
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, EncryptionMode.CBC, (PaddingMode)99, new Des(), DES_IV));
    }

    [Theory]
    [InlineData(EncryptionMode.CBC)]
    [InlineData(EncryptionMode.PCBC)]
    [InlineData(EncryptionMode.CFB)]
    [InlineData(EncryptionMode.OFB)]
    [InlineData(EncryptionMode.CTR)]
    [InlineData(EncryptionMode.RD)]
    public void Context_ModeNeedsIv(EncryptionMode mode)
    {
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, mode, PaddingMode.PKCS7, new Des(), null, 3L));
    }

    [Fact]
    public void Context_EcbWithoutIv_IsFine()
    {
        SymmetricCipher cipher = new SymmetricCipher(DES_KEY, EncryptionMode.ECB, PaddingMode.PKCS7, new Des());
        Assert.Equal([1, 2, 3], cipher.Decrypt(cipher.Encrypt([1, 2, 3])));
    }

    [Fact]
    public void Context_RdDelta()
    {
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, EncryptionMode.RD, PaddingMode.PKCS7, new Des(), DES_IV));
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, EncryptionMode.RD, PaddingMode.PKCS7, new Des(), DES_IV, 0L));
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, EncryptionMode.RD, PaddingMode.PKCS7, new Des(), DES_IV, -3L));
        Assert.Throws<ArgumentException>(() => new SymmetricCipher(DES_KEY, EncryptionMode.RD, PaddingMode.PKCS7, new Des(), DES_IV, "abc"));
    }

    [Theory]
    [InlineData(EncryptionMode.ECB)]
    [InlineData(EncryptionMode.CBC)]
    [InlineData(EncryptionMode.PCBC)]
    public void Context_CiphertextNotMultipleOfBlock(EncryptionMode mode)
    {
        SymmetricCipher cipher = new SymmetricCipher(DES_KEY, mode, PaddingMode.PKCS7, new Des(), DES_IV);
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[13]));
    }

    [Theory]
    [InlineData(PaddingMode.PKCS7)]
    [InlineData(PaddingMode.ANSIX923)]
    public void Context_WrongKey_BadPaddingDetected(PaddingMode padding)
    {
        SymmetricCipher right = new SymmetricCipher(DES_KEY, EncryptionMode.CBC, padding, new Des(), DES_IV);
        SymmetricCipher wrong = new SymmetricCipher(Convert.FromHexString("0E329232EA6D0D73"), EncryptionMode.CBC, padding, new Des(), DES_IV);

        byte[] encrypted = right.Encrypt(new byte[100]);

        Assert.Throws<ArgumentException>(() => wrong.Decrypt(encrypted));
    }

    [Fact]
    public void Context_Pkcs7_AllPaddingBytesChecked()
    {
        SymmetricCipher cipher = new SymmetricCipher(DES_KEY, EncryptionMode.ECB, PaddingMode.PKCS7, new Des());
        Des des = new Des();
        des.SetKey(DES_KEY);

        byte[] forged = des.Encrypt([0x41, 0x42, 0x43, 0x44, 0x45, 0x01, 0x02, 0x03]);

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(forged));
    }

    [Fact]
    public async Task File_Missing()
    {
        SymmetricCipher cipher = new SymmetricCipher(DES_KEY, EncryptionMode.CBC, PaddingMode.PKCS7, new Des(), DES_IV);
        await Assert.ThrowsAsync<FileNotFoundException>(() => cipher.EncryptAsync("/нет/такого/файла.bin", Path.GetTempFileName()));
    }

    [Fact]
    public async Task File_EmptyPath()
    {
        SymmetricCipher cipher = new SymmetricCipher(DES_KEY, EncryptionMode.CBC, PaddingMode.PKCS7, new Des(), DES_IV);
        await Assert.ThrowsAsync<ArgumentException>(() => cipher.EncryptAsync("", "out.bin"));
        await Assert.ThrowsAsync<ArgumentException>(() => cipher.EncryptAsync(Path.GetTempFileName(), " "));
    }

    [Fact]
    public async Task File_SameInputAndOutput_DoesNotDestroySource()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, [1, 2, 3, 4, 5]);
            SymmetricCipher cipher = new SymmetricCipher(DES_KEY, EncryptionMode.CBC, PaddingMode.PKCS7, new Des(), DES_IV);

            await Assert.ThrowsAsync<ArgumentException>(() => cipher.EncryptAsync(path, path));
            Assert.Equal([1, 2, 3, 4, 5], File.ReadAllBytes(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
