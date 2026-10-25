public class DesAdapter : ICipherTransform
{
    public byte[] Transform(byte[] block, byte[] round_key)
    {
        Des des = new Des();
        des.SetKey(round_key);
        return des.Encrypt(block);
    }
}

public class DealKeyExpansion : IKeyExpansion
{
    private static readonly byte[] FIXED_KEY = Convert.FromHexString("0123456789ABCDEF");

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 16 && key.Length != 24 && key.Length != 32) throw new ArgumentException("deal key must be 16, 24 or 32 bytes");

        int parts = key.Length / 8;
        int rounds = parts == 4 ? 8 : 6;

        Des des = new Des();
        des.SetKey(FIXED_KEY);

        byte[][] round_keys = new byte[rounds][];
        byte[] prev = new byte[8];

        for (int i = 0; i < rounds; i++)
        {
            int n = i % parts;
            byte[] part = key[(8 * n)..(8 * n + 8)];
            byte[] input = SymmetricCipher.Xor(part, prev);

            if (i >= parts)
            {
                input[7] ^= (byte)(1 << (i - parts));
            }

            round_keys[i] = des.Encrypt(input);
            prev = round_keys[i];
        }
        return round_keys;
    }
}

public class Deal : ISymmetricCipher
{
    private FeistelNetwork network = new FeistelNetwork(new DealKeyExpansion(), new DesAdapter(), 16);
    public int BlockSize => 16;
    public void SetKey(byte[] key) => network.SetKey(key);
    public byte[] Encrypt(byte[] block) => network.Encrypt(block);
    public byte[] Decrypt(byte[] block) => network.Decrypt(block);
}