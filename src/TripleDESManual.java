import java.util.Arrays;

public class TripleDESManual {

    // Permutação inicial (IP)
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    // Permutação final (IP^-1)
    private static final int[] IP_INV = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    // Expansão (E-box): de 32 para 48 bits
    private static final int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    // Permutação P
    private static final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
    };

    // PC-1 (Permuted Choice 1) para gerar chaves de 56 bits a partir de 64 bits
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    // PC-2 (Permuted Choice 2) para gerar subchaves de 48 bits
    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    // Número de rotações para cada rodada
    private static final int[] SHIFTS = {
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
    };

    // Substituição S-boxes (8 caixas de 4 linhas x 16 colunas)
    private static final int[][][] SBOX = new int[][][] {
            {
                    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
            },
            {
                    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
            },
            {
                    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
            },
            {
                    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
            },
            {
                    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
            },
            {
                    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
            },
            {
                    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
            },
            {
                    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
            }
    };

    public static int[] permute(int[] input, int[] table) {
        int[] output = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            output[i] = input[table[i] - 1];
        }
        return output;
    }

    // Converte string binária para vetor de int
    public static int[] stringToBitArray(String s) {
        int[] bits = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            bits[i] = s.charAt(i) - '0';
        }
        return bits;
    }

    // Converte vetor de bits para string binária
    public static String bitArrayToString(int[] bits) {
        StringBuilder sb = new StringBuilder();
        for (int b : bits) {
            sb.append(b);
        }
        return sb.toString();
    }

    // Rotações à esquerda
    private static int[] leftShift(int[] bits, int n) {
        int[] result = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            result[i] = bits[(i + n) % bits.length];
        }
        return result;
    }

    // Geração das 16 subchaves de 48 bits
    public static int[][] generateSubKeys(int[] key64bits) {
        int[] key56 = permute(key64bits, PC1);
        int[] C = Arrays.copyOfRange(key56, 0, 28);
        int[] D = Arrays.copyOfRange(key56, 28, 56);
        int[][] subKeys = new int[16][48];

        for (int i = 0; i < 16; i++) {
            C = leftShift(C, SHIFTS[i]);
            D = leftShift(D, SHIFTS[i]);
            int[] CD = new int[56];
            System.arraycopy(C, 0, CD, 0, 28);
            System.arraycopy(D, 0, CD, 28, 28);
            subKeys[i] = permute(CD, PC2);
        }

        return subKeys;
    }

    // XOR entre dois vetores
    public static int[] xor(int[] a, int[] b) {
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    // Aplicação das S-boxes (de 48 bits para 32 bits)
    public static int[] sBoxSubstitution(int[] input48) {
        int[] output32 = new int[32];
        for (int i = 0; i < 8; i++) {
            int[] block = Arrays.copyOfRange(input48, i * 6, (i + 1) * 6);
            int row = (block[0] << 1) | block[5];
            int col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4];
            int val = SBOX[i][row][col];
            for (int j = 0; j < 4; j++) {
                output32[i * 4 + (3 - j)] = (val >> j) & 1;
            }
        }
        return output32;
    }

    // Função Feistel F
    public static int[] feistel(int[] R, int[] subKey) {
        int[] expandedR = permute(R, E);
        int[] xorResult = xor(expandedR, subKey);
        int[] sboxResult = sBoxSubstitution(xorResult);
        return permute(sboxResult, P);
    }


    public static int[] encryptDES(int[] plaintext64, int[] key64) {
        int[] permutedInput = permute(plaintext64, IP);
        int[] L = Arrays.copyOfRange(permutedInput, 0, 32);
        int[] R = Arrays.copyOfRange(permutedInput, 32, 64);
        int[][] subKeys = generateSubKeys(key64);

        for (int i = 0; i < 16; i++) {
            int[] f = feistel(R, subKeys[i]);
            int[] newR = xor(L, f);
            L = R;
            R = newR;
        }

        int[] preOutput = new int[64];
        System.arraycopy(R, 0, preOutput, 0, 32);
        System.arraycopy(L, 0, preOutput, 32, 32);
        return permute(preOutput, IP_INV);
    }

    // Descriptografa um bloco de 64 bits com uma chave de 64 bits
    public static int[] decryptDES(int[] ciphertext64, int[] key64) {
        int[] permutedInput = permute(ciphertext64, IP);
        int[] L = Arrays.copyOfRange(permutedInput, 0, 32);
        int[] R = Arrays.copyOfRange(permutedInput, 32, 64);
        int[][] subKeys = generateSubKeys(key64);

        for (int i = 15; i >= 0; i--) {
            int[] f = feistel(R, subKeys[i]);
            int[] newR = xor(L, f);
            L = R;
            R = newR;
        }

        int[] preOutput = new int[64];
        System.arraycopy(R, 0, preOutput, 0, 32);
        System.arraycopy(L, 0, preOutput, 32, 32);
        return permute(preOutput, IP_INV);
    }

    // 3DES com 3 chaves distintas: E(K3, D(K2, E(K1, P)))
    public static int[] encrypt3DES(int[] plaintext64, int[] k1, int[] k2, int[] k3) {
        int[] step1 = encryptDES(plaintext64, k1);
        int[] step2 = decryptDES(step1, k2);
        return encryptDES(step2, k3);
    }

    // 3DES decriptação com 3 chaves: D(K1, E(K2, D(K3, C)))
    public static int[] decrypt3DES(int[] ciphertext64, int[] k1, int[] k2, int[] k3) {
        int[] step1 = decryptDES(ciphertext64, k3);
        int[] step2 = encryptDES(step1, k2);
        return decryptDES(step2, k1);
    }

    public static String asciiToBinary(String input) {
        StringBuilder binary = new StringBuilder();
        for (char c : input.toCharArray()) {
            String charBinary = Integer.toBinaryString(c);
            // Pad each character to 8 bits
            while (charBinary.length() < 8) {
                charBinary = "0" + charBinary;
            }
            binary.append(charBinary);
        }
        return binary.toString();
    }

    public static String binaryToAscii(String binary) {
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteStr = binary.substring(i, Math.min(i + 8, binary.length()));
            ascii.append((char) Integer.parseInt(byteStr, 2));
        }
        return ascii.toString();
    }

    // Pad binary string to multiple of 64 bits
    public static String padTo64Bits(String binary) {
        int padding = 64 - (binary.length() % 64);
        if (padding != 64) {
            StringBuilder padded = new StringBuilder(binary);
            for (int i = 0; i < padding; i++) {
                padded.append('0'); // Using zero padding
            }
            return padded.toString();
        }
        return binary;
    }

    // Process ASCII text through 3DES encryption
    public static String encryptText3DES(String text, String key1, String key2, String key3) {
        // Adiciona padding PKCS#7 antes de converter para binário
        String paddedText = addPKCS7Padding(text);
        // Convert ASCII text to binary
        String binaryText = asciiToBinary(paddedText);
        // Pad to multiple of 64 bits
        binaryText = padTo64Bits(binaryText);

        // Convert keys to binary if they're not already
        String binaryKey1 = padTo64Bits(asciiToBinary(key1)).substring(0, 64);
        String binaryKey2 = key2.length() == 64 ? key2 : asciiToBinary(key2).substring(0, 64);
        String binaryKey3 = key3.length() == 64 ? key3 : asciiToBinary(key3).substring(0, 64);

        StringBuilder encryptedBinary = new StringBuilder();

        // Process each 64-bit block
        for (int i = 0; i < binaryText.length(); i += 64) {
            String block = binaryText.substring(i, Math.min(i + 64, binaryText.length()));
            int[] data = stringToBitArray(block);
            int[] k1 = stringToBitArray(binaryKey1);
            int[] k2 = stringToBitArray(binaryKey2);
            int[] k3 = stringToBitArray(binaryKey3);

            int[] encrypted = encrypt3DES(data, k1, k2, k3);
            encryptedBinary.append(bitArrayToString(encrypted));
        }

        return encryptedBinary.toString();
    }

    // Process binary ciphertext through 3DES decryption
    public static String decryptText3DES(String binaryCipher, String key1, String key2, String key3) {
        // Convert keys to binary if they're not already
        String binaryKey1 = padTo64Bits(asciiToBinary(key1)).substring(0, 64);
        String binaryKey2 = key2.length() == 64 ? key2 : asciiToBinary(key2).substring(0, 64);
        String binaryKey3 = key3.length() == 64 ? key3 : asciiToBinary(key3).substring(0, 64);

        StringBuilder decryptedBinary = new StringBuilder();

        // Process each 64-bit block
        for (int i = 0; i < binaryCipher.length(); i += 64) {
            String block = binaryCipher.substring(i, Math.min(i + 64, binaryCipher.length()));
            int[] data = stringToBitArray(block);
            int[] k1 = stringToBitArray(binaryKey1);
            int[] k2 = stringToBitArray(binaryKey2);
            int[] k3 = stringToBitArray(binaryKey3);

            int[] decrypted = decrypt3DES(data, k1, k2, k3);
            decryptedBinary.append(bitArrayToString(decrypted));
        }

        // Convert binary back to ASCII
        String decryptedText = binaryToAscii(decryptedBinary.toString());
        return removePKCS7Padding(decryptedText);
    }

    // Adiciona padding PKCS#7 ao texto antes de criptografar
    public static String addPKCS7Padding(String text) {
        int padSize = 8 - (text.length() % 8);
        char padChar = (char) padSize;
        return text + String.valueOf(padChar).repeat(padSize);
    }

    // Remove padding PKCS#7 após descriptografar
    public static String removePKCS7Padding(String text) {
        if (text.isEmpty()) return text;
        int padSize = text.charAt(text.length() - 1);
        if (padSize > 0 && padSize <= 8) {
            return text.substring(0, text.length() - padSize);
        }
        return text; // Se não houver padding válido, retorna o original
    }

    public static void main(String[] args) {
        String plaintext = "Socorram-me, subi no ônibus em Marrocos";  // Texto a ser criptografado
        String key1 = "keyword0";       // 8 caracteres (64 bits)
        String key2 = "palavra1";       // 8 caracteres
        String key3 = "chave002";       // 8 caracteres

        System.out.println("Texto original: " + plaintext);

        // Criptografa
        String encrypted = encryptText3DES(plaintext, key1, key2, key3);
        System.out.println("Criptografado (binário): " + encrypted);

        // Decriptografa
        String decrypted = decryptText3DES(encrypted, key1, key2, key3);
        System.out.println("Decriptografado: '" + decrypted +"'");
    }
}
