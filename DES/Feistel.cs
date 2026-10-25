public class FeistelNetwork : ISymmetricCipher
{
    private IKeyExpansion key_expansion;
    private ICipherTransform round_function;
    private byte[][] round_keys = [];

    public int BlockSize { get; }

    public FeistelNetwork(IKeyExpansion key_expansion, ICipherTransform round_function, int block_size)
    {
        if (key_expansion == null) throw new ArgumentNullException(nameof(key_expansion));
        if (round_function == null) throw new ArgumentNullException(nameof(round_function));
        if (block_size <= 0 || block_size % 2 != 0) throw new ArgumentException("block size must be positive and even");

        this.key_expansion = key_expansion;
        this.round_function = round_function;
        BlockSize = block_size;
    }

    public void SetKey(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        round_keys = key_expansion.GenerateRoundKeys(key);
    }

    public byte[] Encrypt(byte[] block) => Run(block, true);
    public byte[] Decrypt(byte[] block) => Run(block, false);
    private byte[] Run(byte[] block, bool forward)
    {
        if (block == null) throw new ArgumentNullException(nameof(block));
        if (round_keys.Length == 0) throw new InvalidOperationException("key is not set");
        if (block.Length != BlockSize) throw new ArgumentException("wrong block length");

        int half = BlockSize / 2;
        byte[] left = block[..half];
        byte[] right = block[half..];

        for (int r = 0; r < round_keys.Length; r++)
        {
            byte[] key = forward ? round_keys[r] : round_keys[^(r + 1)];
            byte[] new_right = SymmetricCipher.Xor(left, round_function.Transform(right, key));
            left = right;
            right = new_right;
        }

        return [.. right, .. left];
    }
}