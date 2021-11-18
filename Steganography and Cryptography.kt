package cryptography

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.File
import java.io.IOException
import java.util.*
import javax.imageio.ImageIO
import kotlin.experimental.xor

const val HIDE = "hide"
const val SHOW = "show"
const val EXIT = "exit"

fun main() {
    val scanner = Scanner(System.`in`)
    var task: Task

    scanner.use {
        while (true) {
            println("Task (hide, show, exit):")
            task = inputToSealedClass(it.nextLine().trim())

            try {
                task.execute(it)
            } catch (ex: IOException) {
                println(ex.message)
            }

            if (task is Task.ExitTask) break
        }
    }
}

fun inputToSealedClass(input: String): Task {
    if (input == HIDE) return Task.HideTask
    if (input == SHOW) return Task.ShowTask
    if (input == EXIT) return Task.ExitTask

    return Task.WrongTask {
        println("Wrong task: $input")
    }
}

sealed class Task {
    abstract fun execute(scanner: Scanner)

    object HideTask : Task() {
        override fun execute(scanner: Scanner) {
            println("Input image file:")
            val inputPath = scanner.nextLine()
            println("Output image file:")
            val outputPath = scanner.nextLine()

            val inputImage = ImageIO.read(File(inputPath))
            val outputImage = BufferedImage(inputImage.width, inputImage.height, BufferedImage.TYPE_INT_RGB)
            val outputImageFile = File(outputPath)

            val messageToHideAsByteArray = readMessage(scanner).encodeToByteArray()
            val passwordAsByteArray = readPassword(scanner).encodeToByteArray()

            val encryptedMessageAsByteArray = encryptMessage(messageToHideAsByteArray, passwordAsByteArray)
            val messageWithTerminatingBytes = addTerminatingBytes(encryptedMessageAsByteArray)

            if (!imageBigEnoughToHideMessage(messageWithTerminatingBytes.size, inputImage.width, inputImage.height)) {
                println("The input image is not large enough to hold this message.")
                return
            }

            generateOutputImageContent(inputImage, outputImage, messageWithTerminatingBytes)

            saveImage(outputImage, outputImageFile)
            println("Message saved in $outputPath image.")
        }

        private fun generateOutputImageContent(
            inputImage: BufferedImage,
            outputImage: BufferedImage,
            messageWithTerminatingBytes: ByteArray
        ) {
            var byteIndex = 0
            var bitShiftIndex = 7
            for (y in 0 until inputImage.height) {
                for (x in 0 until inputImage.width) {
                    if (bitShiftIndex == -1) {
                        bitShiftIndex = 7
                        byteIndex++
                    }
                    if (byteIndex == messageWithTerminatingBytes.size) {
                        outputImage.setRGB(x, y, inputImage.getRGB(x, y))
                    } else {
                        val c = Color(inputImage.getRGB(x, y))
                        val byte = messageWithTerminatingBytes[byteIndex].toInt()
                        val bit = (byte shr bitShiftIndex) and 1
                        val newBlue = if (c.blue % 2 == 0) {
                            c.blue or bit
                        } else {
                            c.blue and (0b11111110 or bit)
                        }
                        val rgb = (c.red shl 16) or (c.green shl 8) or newBlue
                        bitShiftIndex--
                        outputImage.setRGB(x, y, rgb)
                    }
                }
            }
        }

        private fun encryptMessage(messageToHideAsByteArray: ByteArray, passwordAsByteArray: ByteArray): ByteArray {
            val encryptedMessage = ByteArray(messageToHideAsByteArray.size)
            var passwordIndex = 0
            for ((index, messageByte) in messageToHideAsByteArray.withIndex()) {
                if (passwordIndex == passwordAsByteArray.size) passwordIndex = 0
                encryptedMessage[index] = messageByte xor passwordAsByteArray[passwordIndex]
                passwordIndex++
            }
            return encryptedMessage
        }

        private fun addTerminatingBytes(messageToHideAsByteArray: ByteArray): ByteArray {
            val arrayWithTerminatingBytes = messageToHideAsByteArray.copyOf(messageToHideAsByteArray.size + 3)
            arrayWithTerminatingBytes[messageToHideAsByteArray.size] = 0b00000000
            arrayWithTerminatingBytes[messageToHideAsByteArray.size + 1] = 0b00000000
            arrayWithTerminatingBytes[messageToHideAsByteArray.size + 2] = 0b00000011
            return arrayWithTerminatingBytes
        }

        private fun readMessage(scanner: Scanner): String {
            println("Message to hide:")
            return scanner.nextLine()
        }

        private fun readPassword(scanner: Scanner): String {
            println("Password:")
            return scanner.nextLine()
        }

        private fun imageBigEnoughToHideMessage(sizeOfMessage: Int, width: Int, height: Int): Boolean {
            if (sizeOfMessage * 8 > width * height) return false
            return true
        }

        private fun saveImage(image: BufferedImage, imageFile: File) {
            ImageIO.write(image, "png", imageFile)
        }
    }

    object ShowTask : Task() {
        override fun execute(scanner: Scanner) {
            println("Input image file:")
            val inputPath = scanner.nextLine()

            val passwordAsByteArray = readPassword(scanner).encodeToByteArray()

            val inputImage = ImageIO.read(File(inputPath))

            val bytes = getMessageBytes(inputImage)

            val encryptedMessageBytes = messageWithoutTerminatingBytes(bytes)
            val message = decryptMessage(encryptedMessageBytes, passwordAsByteArray)
            println("Message:")
            println(message)
        }

        private fun getMessageBytes(inputImage: BufferedImage): List<Int> {
            val bytes = mutableListOf<Int>()

            var bitShiftIndex = 7
            var byte = 0
            for (y in 0 until inputImage.height) {
                for (x in 0 until inputImage.width) {
                    val c = Color(inputImage.getRGB(x, y))
                    if (bitShiftIndex == -1) {
                        bitShiftIndex = 7
                        bytes.add(byte)
                        byte = 0
                    }
                    val bit = c.blue and 1
                    byte = byte or (bit shl bitShiftIndex)
                    bitShiftIndex--
                }
            }

            return bytes
        }

        private fun decryptMessage(encryptedMessageBytes: ByteArray, passwordAsByteArray: ByteArray): String {
            val decryptedMessage = ByteArray(encryptedMessageBytes.size)
            var passwordIndex = 0
            for ((index, messageByte) in encryptedMessageBytes.withIndex()) {
                if (passwordIndex == passwordAsByteArray.size) passwordIndex = 0
                decryptedMessage[index] = messageByte xor passwordAsByteArray[passwordIndex]
                passwordIndex++
            }
            return decryptedMessage.toString(Charsets.UTF_8)
        }

        private fun messageWithoutTerminatingBytes(bytes: List<Int>): ByteArray {
            var messageBytesAsIntArray: List<Int> = listOf()
            for ((index, byte) in bytes.withIndex()) {
                if (byte == 3) {
                    if (index < 2) continue
                    if (bytes[index - 1] == 0 && bytes[index - 2] == 0) {
                        messageBytesAsIntArray = bytes.subList(0, index - 2)
                        break
                    }
                }
            }

            return messageBytesAsIntArray
                .foldIndexed(ByteArray(messageBytesAsIntArray.size))
                { index, array, value -> array.apply { set(index, value.toByte()) } }
        }

        private fun readPassword(scanner: Scanner): String {
            println("Password:")
            return scanner.nextLine()
        }
    }

    object ExitTask : Task() {
        override fun execute(scanner: Scanner) = println("Bye!")

    }

    class WrongTask(private val function: () -> Unit) : Task() {
        override fun execute(scanner: Scanner) = function()
    }
}