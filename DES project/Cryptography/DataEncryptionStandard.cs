using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//TEORÍA DEL ALGORITMO DES (DATA ENCRYPTION STANDARD)
/*
 DESCIFRADO DES

3 elementos:
-entrada
	-texto plano
	-llave k
	-tablas de conversión
-algoritmo DES
-texto cifrado

PROCESO DEL ALGORITMO

TABLAS -> IP, PC1, SR, PC2, E, S-BOX(8), P, IP-1

ip -> initial permutation
cp1 --> permuted choice 1
cp2 -> permuted choice 2
sr -> schedule rotations
e > expansion function
sbox -> substitution boxes
p -> permutation
ip-1 -> final permutation

A.1) ENTRADA DEL TEXTO PLANO
A.2) BLOQUE DE 8 CARACTERES
1.3) CONVERTIR A BINARIO
A.4) GENERAR MATRIZ DE 8X8
A.5) APLICAR TABLA IP (INITIAL PERMUTATION)

-> 2 TABLAS DE 32 BITS (L0 Y R0)

B.1) ENTRADA DE LLAVE K
B.2) CONVERTIR A BINARIO
B.3) GENERAR MATRIZ DE 8X8
B.4) ELIMINAR ULTIMA COLUMNA (GENERA UNA MATRIZ DE 56 BITS)
B.5) APLICAR PC1 = K PRIMA
B.6) DIVIDIR EN 2 PARTES DE 28 BITS
B.7) APLICAR TABLA (SR)SCROLL A C/U
B.8) JUNTAR PARTES -> PARTE ENTERA

B.8.1) APLICAR PC2 -> GENERA TABLA DE 48 BITS = LLAVE K[i]
B.8.2) RETORNA PARTE ENTERA -> REPITE TODO EL PROCESO DESDE B.6

-> 16 LLAVES K

Li = Ri-1
Ri = Li-1 (XOR) f(Ri-1 K [i])

TENGO L0 Y R0, Y 16 LLAVES
<-- VUELTA 1 -->
C.1) APLICAR TABLA E (EXPAND) A R0(A R0 SE CONVIERTE DE 32 A -> 48 BITS)
C.2) APLICAR XOR A R0 + K[i] = L[i + 1] -> R0 = L1
C.3) APLICAR TABLA S-BOX (MUY COMPLEJA) GENERA TABLA DE 32 BITS
C.4) APLICAR TABLA P A RESULTANTE
C.4) APLICAR XOR A RESULTANTE + L0 = R1
<-- VUELTA 2 -->
C.5) APLICAR TABLA E (EXPAND) A R1
C.2) APLICAR XOR A R1 + K[i] = L[i + 1] -> R1 = L2
C.3) APLICAR TABLA S-BOX (MUY COMPLEJA) GENERA TABLA DE 32 BITS
C.4) APLICAR TABLA P A RESULTANTE
C.4) APLICAR XOR A RESULTANTE + L1 = R2
...
16 VUELTAS

FINAL.1) JUNTAR R16 + L16 (NO L16 + R16)
FINAL.2) APLICAR IP-1

-> MENSAJE ENCRIPTADO

REPETIR POR CADA BLOQUE DEL MENSAJE
*/

namespace Cryptography
{
    class DataEncryptionStandard : DESentitites
    {
        new Message Message;

        public string Encrypt(string MessageToEncrypt, string Key)
        {
            Algorythm(MessageToEncrypt, Key);
            return Message.MessageEncrypted;
        }

        private void Algorythm(string MessageToEncrypt, string Key)
        {
            //Instancia de un nuevo objeto tipo "Message".
            Message = new Message(MessageToEncrypt, Key);

            //Conjunto de bloques de texto de 8 caracteres
            Block[] Blocks = CreateBlocks(Message.MessageNoEcrypted);

            //ENCRIPTACIÓN DE CADA BLOQUE DE 8 CARACTERES
            for (int i = 0; i < Blocks.Length; i++)
            {
                //Convierte el bloque a encriptar a binario
                Blocks[i].BinaryMessage = ConvertStringToBin(Blocks[i].SubMessage);

                //matriz de 64 bits de tamaño 8x8
                Box Box = new Box(8, 8, Blocks[i].BinaryMessage);
            }

        }

        private Block[] CreateBlocks(string msg)
        {
            int BlocksNumber = msg.Length / 8;
            Block[] Blocks = new Block[BlocksNumber];

            for (int i = 0; i < BlocksNumber; i++)
            {
                Block B = new Block(msg.Substring(i * 8, 8));
                Blocks[i] = B;
            }

            return Blocks;
        }

        byte[] ConvertStringToBin(string block)
        {
            int Count = 0;
            byte[] binary = new byte[64];
            foreach (char C in block)
            {
                string temp = Convert.ToString(C, 2).PadLeft(8, '0');
                for (int i = 0; i < 8; i++)
                {
                    binary[Count] = Convert.ToByte(temp.Substring(i,1));
                    Count++;
                }
            }
            return binary;
        }

        string ConvertBinToString(byte[] binary)
        {
            return Encoding.UTF8.GetString(binary);
        }
    }

    class DESentitites
    {

        internal class Message
        {
            public Message(string msg, string key)
            {
                MessageNoEcrypted = msg;
                Key = key;
            }

            public string MessageNoEcrypted { get; set; }
            public string MessageEncrypted { get; set; }
            public string Key { get; set; }
        }
        internal class Box
        {
            public Box(int x, int y)
            {
                SetBoxSize(x, y);
            }

            public Box(int x, int y, byte[] binary)
            {
                SetBoxSize(x, y);
                CreateMatrix(binary);
            }

            public byte[,] Matrix { get; set; }
            public int X { get; set; }
            public int Y { get; set; }
            public int SizeBytes { get; set; }

            public void SetBoxSize(int SizeX, int SizeY)
            {
                X = SizeX;
                Y = SizeY;
                SizeBytes = X * Y;
                Matrix = new byte[Y, X];
            }

            public void CreateMatrix(byte[] binary)
            {
                int Count = 0;
                for (int i = 0; i < Y; i++)
                    for (int j = 0; j < X; j++)
                    {
                        Matrix[i, j] = binary[Count];
                        Count++;
                    }
            }
        }
        internal class Block
        {
            public Block(string SubMsg)
            {
                SubMessage = SubMsg;
            }
            public string SubMessage { get; set; }
            public byte[] BinaryMessage { get; set; }
        }

        internal class DEStables
        {
            // TABLAS -> IP, PC1, SR, PC2, E, S-BOX(8), P, IP-1

            public Box[] TableIP(Box box)
            {
                Box[] IP = new Box[2];
                Box Left = new Box(8, 4);
                Box Right = new Box(8, 4);

                for (int i = 0; i < 8; i++)
                {
                    //PARES
                    Left.Matrix[7 - i, 0] = box.Matrix[0 + i, 1];
                    Left.Matrix[7 - i, 1] = box.Matrix[0 + i, 3];
                    Left.Matrix[7 - i, 2] = box.Matrix[0 + i, 5];
                    Left.Matrix[7 - i, 3] = box.Matrix[0 + i, 7];

                    //IMPARES
                    Right.Matrix[7 - i, 0] = box.Matrix[0 + i, 0];
                    Right.Matrix[7 - i, 1] = box.Matrix[0 + i, 2];
                    Right.Matrix[7 - i, 2] = box.Matrix[0 + i, 4];
                    Right.Matrix[7 - i, 3] = box.Matrix[0 + i, 6];
                }

                IP[0] = Left;
                IP[1] = Right;

                return IP;
            }

            public void TablePC1(Box box)
            {
                Box[] PC1 = new Box[2];
                Box Left = new Box(7, 4);
                Box Right = new Box(7, 4);

                // M [ Y, X ]

                for (int i = 0; i < 8; i++)
                {
                    if (i < 7) // primeros 7
                        Left.Matrix[0, i] = box.Matrix[7 - i, 0];
                    else       // agrega 1
                        Left.Matrix[1, i - 7] = box.Matrix[7 - i, 0];
                    if (i < 6) // siguientes 6
                        Left.Matrix[1, i + 1] = box.Matrix[7 - i, 1];
                    else       // agrega 2
                        Left.Matrix[2, i - 6] = box.Matrix[7 + 1 - i, 1];
                    if (i < 5) // siguientes 5
                        Left.Matrix[2, i + 2] = box.Matrix[7 - i, 2];
                    else       // agrega 3
                        Left.Matrix[3, i - 5] = box.Matrix[7 + 2 - i, 2];
                    if (i < 4) // siguientes 4
                        Left.Matrix[3, i + 3] = box.Matrix[7 - i, 3];
                    else       // ultimos 4
                        Right.Matrix[4, i] = box.Matrix[7 + 3 - i, 3];

                    if (i < 7) // primeros 7
                        Left.Matrix[4, i] = box.Matrix[7 - i, 7];
                    else       // agrega 1
                        Left.Matrix[5, i - 7] = box.Matrix[7 - i, 6];
                    if (i < 6)
                        Right.Matrix[5, i + 1] = box.Matrix[7 - i, 5];
                    if (i < 5)
                        Right.Matrix[i + 2, 6] = box.Matrix[7 - i, 4];
                    if (i < 4)
                        Right.Matrix[i + 3, 7] = box.Matrix[4 - i, 3];


                    Right.Matrix[i, 4] = box.Matrix[7 - i, 6];



                }
            }

            public void TableSR()
            {

            }

            public void TablePC2()
            {

            }

            public void TableE()
            {

            }

            public void TableBox()
            {

            }

            public void TableP()
            {

            }

            public void TableIPinverse()
            {

            }
        }
    }
}
