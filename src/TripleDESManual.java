import java.util.Arrays;

public class TripleDESManual {

    /**
     * Aplica uma permutação usando uma tabela específica
     * @param input Vetor de bits de entrada
     * @param table Tabela de permutação a ser aplicada
     * @return Vetor de bits permutado
     */
    public static int[] permute(int[] input, int[] table) {
        int[] output = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            output[i] = input[table[i] - 1];
        }
        return output;
    }

    /**
     * Converte uma string binária (composta por '0's e '1's) em um vetor de inteiros.
     * Cada caractere da string é convertido para um valor inteiro (0 ou 1).
     *
     * @param s String binária a ser convertida (ex: "101010")
     * @return Vetor de inteiros onde cada elemento representa um bit (ex: [1, 0, 1, 0, 1, 0])
     */
    public static int[] stringToBitArray(String s) {
        int[] bits = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            bits[i] = s.charAt(i) - '0';
        }
        return bits;
    }

    /**
     * Converte um vetor de bits (valores inteiros 0 ou 1) em uma string binária.
     *
     * @param bits Vetor de inteiros representando bits (ex: [1, 0, 1, 0])
     * @return String binária concatenada (ex: "1010")
     */
    public static String bitArrayToString(int[] bits) {
        StringBuilder sb = new StringBuilder();
        for (int b : bits) {
            sb.append(b);
        }
        return sb.toString();
    }

    /**
     * Realiza uma rotação circular à esquerda (left shift) em um array de bits.
     * Os bits que "saem" do início são reinseridos no final do array.
     *
     * @param bits Array de bits a ser rotacionado (ex: [1, 0, 0, 1])
     * @param n Número de posições para rotacionar (ex: 2)
     * @return Novo array com os bits rotacionados (ex: [0, 1, 1, 0] para n=2)
     */
    private static int[] leftShift(int[] bits, int n) {
        int[] result = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            result[i] = bits[(i + n) % bits.length];
        }
        return result;
    }

    /**
     * Gera as 16 subchaves para o DES
     * @param key64bits Chave de 64 bits (com bits de paridade)
     * @return Array com as 16 subchaves de 48 bits
     */
    public static int[][] generateSubKeys(int[] key64bits) {
        int[] key56 = permute(key64bits, Tables.PC1);
        int[] C = Arrays.copyOfRange(key56, 0, 28);
        int[] D = Arrays.copyOfRange(key56, 28, 56);
        int[][] subKeys = new int[16][48];

        for (int i = 0; i < 16; i++) {
            C = leftShift(C, Tables.SHIFTS[i]);
            D = leftShift(D, Tables.SHIFTS[i]);
            int[] CD = new int[56];
            System.arraycopy(C, 0, CD, 0, 28);
            System.arraycopy(D, 0, CD, 28, 28);
            subKeys[i] = permute(CD, Tables.PC2);
        }

        return subKeys;
    }

    /**
     * Realiza uma operação XOR (OU exclusivo) bit-a-bit entre dois vetores de inteiros.
     *
     * Este método é fundamental para o processo de criptografia DES/3DES, sendo utilizado:
     * - Na função Feistel para combinar o texto expandido com a subchave
     * - Em várias etapas de mistura (diffusion) do algoritmo
     *
     * @param a Primeiro vetor de bits (deve conter apenas 0s e 1s)
     * @param b Segundo vetor de bits (deve ter o mesmo comprimento de 'a')
     * @return Novo vetor contendo o resultado do XOR entre cada bit correspondente
     */
    public static int[] xor(int[] a, int[] b) {
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    /**
     * Executa uma rodada de substituição S-box
     * @param input48 Bloco de 48 bits
     * @return Bloco reduzido para 32 bits
     */
    public static int[] sBoxSubstitution(int[] input48) {
        int[] output32 = new int[32];
        for (int i = 0; i < 8; i++) {
            int[] block = Arrays.copyOfRange(input48, i * 6, (i + 1) * 6);
            int row = (block[0] << 1) | block[5];
            int col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4];
            int val = Tables.SBOX[i][row][col];
            for (int j = 0; j < 4; j++) {
                output32[i * 4 + (3 - j)] = (val >> j) & 1;
            }
        }
        return output32;
    }

    /**
     * Função Feistel (F) - Coração do DES
     * @param R Metade direita de 32 bits
     * @param subKey Subchave de 48 bits para esta rodada
     * @return Resultado de 32 bits da função F
     */
    public static int[] feistel(int[] R, int[] subKey) {
        int[] expandedR = permute(R, Tables.E);
        int[] xorResult = xor(expandedR, subKey);
        int[] sboxResult = sBoxSubstitution(xorResult);
        return permute(sboxResult, Tables.P);
    }

    /**
     * Criptografa um bloco de 64 bits usando o algoritmo DES padrão.
     *
     * Este método implementa o fluxo principal do DES:
     * 1. Aplica a permutação inicial (IP)
     * 2. Divide o bloco em dois halves (L0 e R0) de 32 bits cada
     * 3. Executa 16 rodadas Feistel
     * 4. Troca os halves finais (R16 e L16)
     * 5. Aplica a permutação inversa (IP^-1)
     *
     * @param plaintext64 Bloco de texto claro de 64 bits (como array de ints 0/1)
     * @param key64 Chave de 64 bits (incluindo bits de paridade não usados)
     * @return Bloco cifrado de 64 bits
     */
    public static int[] encryptDES(int[] plaintext64, int[] key64) {
        int[] permutedInput = permute(plaintext64, Tables.IP);
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
        return permute(preOutput, Tables.IP_INV);
    }

    /**
     * Decriptografa um bloco de 64 bits usando o algoritmo DES padrão.
     *
     * O processo é idêntico à criptografia, mas com as subchaves aplicadas
     * em ordem inversa (K16 até K1). Isso aproveita a estrutura reversível do DES.
     *
     * @param ciphertext64 Bloco cifrado de 64 bits (como array de ints 0/1)
     * @param key64 Chave de 64 bits (deve ser a mesma usada na criptografia)
     * @return Bloco de texto claro de 64 bits
     */
    public static int[] decryptDES(int[] ciphertext64, int[] key64) {
        int[] permutedInput = permute(ciphertext64, Tables.IP);
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
        return permute(preOutput, Tables.IP_INV);
    }

    /**
     * Criptografa usando 3DES com três chaves (EDE)
     * Padrão: C = E(K3, D(K2, E(K1, P)))
     * @param plaintext64 Bloco de 64 bits de texto claro
     * @param k1 Primeira chave de 64 bits
     * @param k2 Segunda chave de 64 bits
     * @param k3 Terceira chave de 64 bits
     * @return Texto cifrado de 64 bits
     */
    public static int[] encrypt3DES(int[] plaintext64, int[] k1, int[] k2, int[] k3) {
        int[] step1 = encryptDES(plaintext64, k1);
        int[] step2 = decryptDES(step1, k2);
        return encryptDES(step2, k3);
    }

    /**
     * Decripta usando 3DES com três chaves (EDE)
     * Padrão: P = D(K1, E(K2, D(K3, C)))
     * @param ciphertext64 Bloco de 64 bits de texto cifrado
     * @param k1 Primeira chave de 64 bits
     * @param k2 Segunda chave de 64 bits
     * @param k3 Terceira chave de 64 bits
     * @return Texto claro de 64 bits
     */
    public static int[] decrypt3DES(int[] ciphertext64, int[] k1, int[] k2, int[] k3) {
        int[] step1 = decryptDES(ciphertext64, k3);
        int[] step2 = encryptDES(step1, k2);
        return decryptDES(step2, k1);
    }

    /**
     * Converte texto ASCII para representação binária (string de bits)
     * @param input String ASCII
     * @return String binária representando o texto
     */
    public static String asciiToBinary(String input) {
        StringBuilder binary = new StringBuilder();
        for (char c : input.toCharArray()) {
            String charBinary = Integer.toBinaryString(c);
            while (charBinary.length() < 8) {
                charBinary = "0" + charBinary;
            }
            binary.append(charBinary);
        }
        return binary.toString();
    }

    /**
     * Converte string binária para texto ASCII
     * @param binary String de bits (0s e 1s)
     * @return String ASCII correspondente
     */
    public static String binaryToAscii(String binary) {
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteStr = binary.substring(i, Math.min(i + 8, binary.length()));
            ascii.append((char) Integer.parseInt(byteStr, 2));
        }
        return ascii.toString();
    }

    /**
     * Realiza o padding (preenchimento) de uma string binária para que seu tamanho seja múltiplo de 64 bits.
     *
     * Este método é essencial para o processamento de dados no DES/3DES, que opera em blocos fixos de 64 bits.
     * Caso o tamanho original não seja múltiplo de 64 bits, adiciona zeros ('0') ao final até completar.
     *
     * @param binary String binária a ser padronizada (composta por '0's e '1's)
     * @return String binária com tamanho múltiplo de 64 bits
     */
    public static String padTo64Bits(String binary) {
        int padding = 64 - (binary.length() % 64);
        if (padding != 64) {
            StringBuilder padded = new StringBuilder(binary);
            for (int i = 0; i < padding; i++) {
                padded.append('0');
            }
            return padded.toString();
        }
        return binary;
    }

    /**
     * Criptografa texto ASCII usando o algoritmo 3DES (Triple DES) no modo EDE (Encrypt-Decrypt-Encrypt).
     *
     * O processo completo inclui:
     * 1. Padding PKCS#7 do texto original
     * 2. Conversão para representação binária
     * 3. Divisão em blocos de 64 bits
     * 4. Aplicação do 3DES em cada bloco com as três chaves
     *
     * @param text Texto claro em formato ASCII
     * @param key1 Primeira chave (8 caracteres ASCII ou 64 bits binários)
     * @param key2 Segunda chave (8 caracteres ASCII ou 64 bits binários)
     * @param key3 Terceira chave (8 caracteres ASCII ou 64 bits binários)
     * @return Texto cifrado em representação binária (string de 0s e 1s)
     */
    public static String encryptText3DES(String text, String key1, String key2, String key3) {
        String paddedText = addPKCS7Padding(text);
        String binaryText = asciiToBinary(paddedText);
        binaryText = padTo64Bits(binaryText);

        String binaryKey1 = padTo64Bits(asciiToBinary(key1)).substring(0, 64);
        String binaryKey2 = key2.length() == 64 ? key2 : asciiToBinary(key2).substring(0, 64);
        String binaryKey3 = key3.length() == 64 ? key3 : asciiToBinary(key3).substring(0, 64);

        StringBuilder encryptedBinary = new StringBuilder();

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

    /**
     * Descriptografa texto cifrado binário usando o algoritmo 3DES (Triple DES) no modo DED (Decrypt-Encrypt-Decrypt).
     *
     * O processo inverso inclui:
     * 1. Processamento de cada bloco de 64 bits
     * 2. Aplicação do 3DES reverso com as três chaves
     * 3. Conversão do resultado binário para ASCII
     * 4. Remoção do padding PKCS#7
     *
     * @param binaryCipher Texto cifrado em formato binário (string de 0s e 1s)
     * @param key1 Primeira chave (deve ser a mesma usada na criptografia)
     * @param key2 Segunda chave (deve ser a mesma usada na criptografia)
     * @param key3 Terceira chave (deve ser a mesma usada na criptografia)
     * @return Texto claro original em formato ASCII
     */
    public static String decryptText3DES(String binaryCipher, String key1, String key2, String key3) {
        String binaryKey1 = padTo64Bits(asciiToBinary(key1)).substring(0, 64);
        String binaryKey2 = key2.length() == 64 ? key2 : asciiToBinary(key2).substring(0, 64);
        String binaryKey3 = key3.length() == 64 ? key3 : asciiToBinary(key3).substring(0, 64);

        StringBuilder decryptedBinary = new StringBuilder();

        for (int i = 0; i < binaryCipher.length(); i += 64) {
            String block = binaryCipher.substring(i, Math.min(i + 64, binaryCipher.length()));
            int[] data = stringToBitArray(block);
            int[] k1 = stringToBitArray(binaryKey1);
            int[] k2 = stringToBitArray(binaryKey2);
            int[] k3 = stringToBitArray(binaryKey3);

            int[] decrypted = decrypt3DES(data, k1, k2, k3);
            decryptedBinary.append(bitArrayToString(decrypted));
        }

        String decryptedText = binaryToAscii(decryptedBinary.toString());
        return removePKCS7Padding(decryptedText);
    }

    /**
     * Adiciona padding PKCS#7 para garantir múltiplos de 8 bytes
     * @param text Texto de entrada
     * @return Texto com padding adicionado
     */
    public static String addPKCS7Padding(String text) {
        int padSize = 8 - (text.length() % 8);
        char padChar = (char) padSize;
        return text + String.valueOf(padChar).repeat(padSize);
    }

    /**
     * Remove padding PKCS#7 após decriptação
     * @param text Texto com padding
     * @return Texto original sem padding
     */
    public static String removePKCS7Padding(String text) {
        if (text.isEmpty()) return text;
        int padSize = text.charAt(text.length() - 1);
        if (padSize > 0 && padSize <= 8) {
            return text.substring(0, text.length() - padSize);
        }
        return text;
    }

    /**
     * Método principal demonstra o uso do 3DES
     * 1. Criptografa texto com 3 chaves
     * 2. Decripta o resultado
     * 3. Mostra o texto original e decriptado
     */
    public static void main(String[] args) {
        String plaintext = "Socorram-me, subi no ônibus em Marrocos";
        String key1 = "tamyles1";
        String key2 = "leonardo";
        String key3 = "rosane44";

        System.out.println("Texto original: " + plaintext);

        // Criptografa (3DES EDE)
        String encrypted = encryptText3DES(plaintext, key1, key2, key3);
        System.out.println("Criptografado (binário): " + encrypted);

        // Decriptografa (3DES DED)
        String decrypted = decryptText3DES(encrypted, key1, key2, key3);
        System.out.println("Decriptografado: '" + decrypted +"'");
    }
}
