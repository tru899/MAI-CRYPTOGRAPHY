public enum BitIndexing
{
    IS_ZERO,
    IS_ONE
}

public enum BitOrder
{
    fromLSBtoMSB,
    fromMSBtoLSB
}


public class Bits
{
    const int BYTE_LENGHT = sizeof(byte) * 8;

    public byte[] Permute(byte[] value, int[] pblock, BitIndexing index, BitOrder order)
    {
        if (value == null) { throw new ArgumentNullException(nameof(value)); }
        if (pblock == null) { throw new ArgumentNullException(nameof(pblock)); }
        if (pblock.Length == 0) { throw new ArgumentException("p-block is empty", nameof(pblock)); }

        int byte_place, position, new_pblock, bit_value;
        byte[] res = new byte[(pblock.Length + 7) / BYTE_LENGHT];

        for (int i = 0; i < pblock.Length; i++) {
            if (index == BitIndexing.IS_ZERO) {
                if (pblock[i] < 0 || pblock[i] >= value.Length * 8) { throw new ArgumentOutOfRangeException(nameof(pblock), pblock[i], "номер бита вне интервала"); }
                new_pblock = pblock[i];
            }
            else
            {
                if (pblock[i] < 1 || pblock[i] > value.Length * 8) { throw new ArgumentOutOfRangeException(nameof(pblock), pblock[i], "номер бита вне интервала"); }
                new_pblock = pblock[i] - 1;
            }

            if (order == BitOrder.fromMSBtoLSB)
            {
                byte_place = new_pblock / BYTE_LENGHT;
                position = 7 - new_pblock % BYTE_LENGHT;
            }
            else
            {
                byte_place = (value.Length - 1) - new_pblock / BYTE_LENGHT;
                position = new_pblock % BYTE_LENGHT;
            }

            bit_value = (value[byte_place] >> position) & 1;
            
            if (order == BitOrder.fromMSBtoLSB)
            {
                res[i / BYTE_LENGHT] |= (byte)(bit_value << (7 - i % BYTE_LENGHT));
            }
            else
            {
                res[(res.Length - 1) - i / BYTE_LENGHT] |= (byte)(bit_value << (i % BYTE_LENGHT));
            }
        }
        return res;
    }
}
