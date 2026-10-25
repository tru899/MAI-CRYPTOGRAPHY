namespace DES.Tests;

public class PermutationTests
{
    private readonly Bits bits = new Bits();

    [Fact]
    public void Identity_KeepsValue()
    {
        byte[] value = [0xA5, 0x3C];
        int[] rule = [.. Enumerable.Range(1, 16)];

        Assert.Equal(value, bits.Permute(value, rule, BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB));
        Assert.Equal(value, bits.Permute(value, [.. Enumerable.Range(0, 16)], BitIndexing.IS_ZERO, BitOrder.fromLSBtoMSB));
    }

    [Fact]
    public void ReverseByte()
    {
        Assert.Equal([0x03], bits.Permute([0xC0], [8, 7, 6, 5, 4, 3, 2, 1], BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB));
    }

    [Fact]
    public void ResultLength_ComesFromRule()
    {
        int[] rule = [.. Enumerable.Range(0, 48).Select(i => i % 32 + 1)];

        Assert.Equal(6, bits.Permute(new byte[4], rule, BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB).Length);
    }

    [Fact]
    public void DesInitialPermutation()
    {
        int[] ip =
        [
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
        ];

        byte[] result = bits.Permute(Convert.FromHexString("0123456789ABCDEF"), ip, BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB);

        Assert.Equal("CC00CCFFF0AAF0AA", Convert.ToHexString(result));
    }

    [Fact]
    public void BitOutsideValue_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => bits.Permute([0, 0], [16], BitIndexing.IS_ZERO, BitOrder.fromMSBtoLSB));
        Assert.Throws<ArgumentOutOfRangeException>(() => bits.Permute([0, 0], [0], BitIndexing.IS_ONE, BitOrder.fromMSBtoLSB));
    }
}

public class FeistelTests
{
    private class Keys : IKeyExpansion
    {
        public byte[][] GenerateRoundKeys(byte[] key) =>
            [.. Enumerable.Range(0, 16).Select(r => key.Select(k => (byte)(k + r * 31)).ToArray())];
    }

    private class LossyF : ICipherTransform
    {
        public byte[] Transform(byte[] block, byte[] key) =>
            [.. block.Select((b, i) => (byte)((b * b + key[i % key.Length]) & 0xF0))];
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    public void DecryptRestores_WithNonInvertibleF(int block_size)
    {
        FeistelNetwork network = new FeistelNetwork(new Keys(), new LossyF(), block_size);
        network.SetKey([1, 2, 3, 4, 5, 6, 7, 8]);
        Random random = new Random(1);

        for (int i = 0; i < 200; i++)
        {
            byte[] block = new byte[block_size];
            random.NextBytes(block);
            Assert.Equal(block, network.Decrypt(network.Encrypt(block)));
        }
    }
}

public class DesTests
{
    [Theory]
    [InlineData("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405")]
    [InlineData("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7")]
    [InlineData("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58")]
    public void KnownVectors(string key, string plain, string cipher)
    {
        Des des = new Des();
        des.SetKey(Convert.FromHexString(key));

        byte[] encrypted = des.Encrypt(Convert.FromHexString(plain));

        Assert.Equal(cipher, Convert.ToHexString(encrypted));
        Assert.Equal(plain, Convert.ToHexString(des.Decrypt(encrypted)));
    }

    [Fact]
    public void KeySchedule()
    {
        byte[][] keys = new DesKeyExpansion().GenerateRoundKeys(Convert.FromHexString("133457799BBCDFF1"));

        Assert.Equal(16, keys.Length);
        Assert.Equal("1B02EFFC7072", Convert.ToHexString(keys[0]));
        Assert.Equal("79AED9DBC9E5", Convert.ToHexString(keys[1]));
        Assert.Equal("CB3D8B0E17F5", Convert.ToHexString(keys[15]));
    }

    [Fact]
    public void RoundFunction()
    {
        byte[] f = new DesRoundFunction().Transform(Convert.FromHexString("F0AAF0AA"), Convert.FromHexString("1B02EFFC7072"));

        Assert.Equal("234AA9BB", Convert.ToHexString(f));
    }

    [Theory]
    [InlineData("0101010101010101")]
    [InlineData("FEFEFEFEFEFEFEFE")]
    public void WeakKey_EncryptTwiceGivesPlain(string key)
    {
        Des des = new Des();
        des.SetKey(Convert.FromHexString(key));
        byte[] block = Convert.FromHexString("DEADBEEF01020304");

        Assert.Equal(block, des.Encrypt(des.Encrypt(block)));
    }
}

public class DealTests
{
    private static readonly byte[] KEY_128 = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

    [Fact]
    public void KeySchedule()
    {
        byte[][] keys = new DealKeyExpansion().GenerateRoundKeys(KEY_128);

        Assert.Equal(6, keys.Length);
        Assert.Equal("CADB6782EE2B4823", Convert.ToHexString(keys[0]));
        Assert.Equal("14374EA44D0C167F", Convert.ToHexString(keys[5]));
    }

    [Theory]
    [InlineData(16, 6)]
    [InlineData(24, 6)]
    [InlineData(32, 8)]
    public void RoundCount(int key_length, int rounds)
    {
        Assert.Equal(rounds, new DealKeyExpansion().GenerateRoundKeys(new byte[key_length]).Length);
    }

    [Fact]
    public void ReferenceBlock()
    {
        Deal deal = new Deal();
        deal.SetKey(KEY_128);
        byte[] plain = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

        byte[] encrypted = deal.Encrypt(plain);

        Assert.Equal("49FB7EA389F412639EBF4322349BE102", Convert.ToHexString(encrypted));
        Assert.Equal(plain, deal.Decrypt(encrypted));
    }

    [Fact]
    public void Adapter_IsPlainDes()
    {
        byte[] f = new DesAdapter().Transform(Convert.FromHexString("0123456789ABCDEF"), Convert.FromHexString("133457799BBCDFF1"));

        Assert.Equal("85E813540F0AB405", Convert.ToHexString(f));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void RoundTrip_EveryKeyLength(int key_length)
    {
        Random random = new Random(key_length);
        byte[] key = new byte[key_length];
        random.NextBytes(key);
        Deal deal = new Deal();
        deal.SetKey(key);

        for (int i = 0; i < 50; i++)
        {
            byte[] block = new byte[16];
            random.NextBytes(block);
            Assert.Equal(block, deal.Decrypt(deal.Encrypt(block)));
        }
    }
}

public class PropertyTests
{
    private static int DifferentBits(byte[] a, byte[] b) =>
        a.Zip(b).Sum(p => System.Numerics.BitOperations.PopCount((uint)(p.First ^ p.Second)));

    [Fact]
    public void Des_DifferentKeys_DifferentCiphertext()
    {
        Des a = new Des(); a.SetKey(Convert.FromHexString("133457799BBCDFF1"));
        Des b = new Des(); b.SetKey(Convert.FromHexString("133457799BBCDFF3"));
        byte[] block = Convert.FromHexString("0123456789ABCDEF");

        Assert.NotEqual(a.Encrypt(block), b.Encrypt(block));
    }

    [Fact]
    public void Des_ParityBits_DoNotMatter()
    {
        Des a = new Des(); a.SetKey(Convert.FromHexString("133457799BBCDFF1"));
        Des b = new Des(); b.SetKey(Convert.FromHexString("123456789ABCDEF0"));
        byte[] block = Convert.FromHexString("0123456789ABCDEF");

        Assert.Equal(a.Encrypt(block), b.Encrypt(block));
    }

    [Fact]
    public void Des_Avalanche()
    {
        Des des = new Des(); des.SetKey(Convert.FromHexString("133457799BBCDFF1"));
        byte[] block = Convert.FromHexString("0123456789ABCDEF");
        byte[] flipped = (byte[])block.Clone(); flipped[0] ^= 0x80;

        Assert.InRange(DifferentBits(des.Encrypt(block), des.Encrypt(flipped)), 20, 44);
    }

    [Fact]
    public void Deal_Avalanche()
    {
        Deal deal = new Deal(); deal.SetKey(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"));
        byte[] block = new byte[16];
        byte[] flipped = new byte[16]; flipped[15] = 0x01;

        Assert.InRange(DifferentBits(deal.Encrypt(block), deal.Encrypt(flipped)), 44, 84);
    }

    [Fact]
    public void Deal_DifferentKeys_DifferentCiphertext()
    {
        Deal a = new Deal(); a.SetKey(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"));
        Deal b = new Deal(); b.SetKey(Convert.FromHexString("00112233445566778899AABBCCDDEEFE"));
        byte[] block = new byte[16];

        Assert.NotEqual(a.Encrypt(block), b.Encrypt(block));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void Deal_RoundKeys_AllDistinct(int key_length)
    {
        byte[][] keys = new DealKeyExpansion().GenerateRoundKeys(new byte[key_length]);

        Assert.Equal(keys.Length, keys.Select(Convert.ToHexString).Distinct().Count());
    }

    [Fact]
    public void Deal_SamePrefix_FirstTwoRoundKeysMatch()
    {
        byte[] k128 = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] k192 = Convert.FromHexString("00112233445566778899AABBCCDDEEFF0123456789ABCDEF");

        byte[][] a = new DealKeyExpansion().GenerateRoundKeys(k128);
        byte[][] b = new DealKeyExpansion().GenerateRoundKeys(k192);

        Assert.Equal(a[0], b[0]);
        Assert.Equal(a[1], b[1]);
        Assert.NotEqual(a[2], b[2]);
    }
}
