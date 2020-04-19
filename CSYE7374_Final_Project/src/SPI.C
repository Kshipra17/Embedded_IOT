#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <linux/i2c-dev.h>
#include <linux/spi/spidev.h>
#include <sys/ioctl.h>

unsigned short dig_T1;
short dig_T2;
short dig_T3;

typedef int BMP280_S32_t;

BMP280_S32_t t_fine;
BMP280_S32_t bmp280_compensate_T_int32(BMP280_S32_t adc_T)
{
	BMP280_S32_t var1, var2, T;
	var1 = ((((adc_T>>3) - ((BMP280_S32_t)dig_T1<<1))) * ((BMP280_S32_t)dig_T2)) >> 11;
	var2 = (((((adc_T>>4) - ((BMP280_S32_t)dig_T1)) * ((adc_T>>4) - ((BMP280_S32_t)dig_T1))) >> 12) * ((BMP280_S32_t)dig_T3)) >> 14;
	t_fine = var1 + var2;
	T = (t_fine * 5 + 128) >> 8;

	return T;
}

void spiWriteAndRead(int fd, unsigned char *write, int writeLen,
		    unsigned char *read, int readLen)
{
	struct spi_ioc_transfer spi;
	memset(&spi, 0, sizeof(spi));
	spi.tx_buf = (unsigned long)write;
	spi.len = writeLen;

	if (readLen)
	{
		spi.cs_change = 1;
	}

	ioctl(fd, SPI_IOC_MESSAGE(1), &spi);

	if (readLen)
	{
		memset(&spi, 0, sizeof(spi));
		spi.rx_buf = (unsigned long)read;
		spi.len = readLen;
		ioctl(fd, SPI_IOC_MESSAGE(1), &spi);
	}
}

int main()
{
	unsigned char spiMode;
	unsigned char spiBitsPerWord;
	unsigned int spiSpeed;
	spiMode = SPI_MODE_0;
	spiBitsPerWord = 8;
	spiSpeed = 1000000;		//1000000 = 1MHz (1uS per bit)

	int fd = open("/dev/spidev0.0", O_RDWR);

	ioctl(fd, SPI_IOC_WR_MODE, &spiMode);
	ioctl(fd, SPI_IOC_RD_MODE, &spiMode);
	ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &spiBitsPerWord);
	ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &spiBitsPerWord);
	ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &spiSpeed);
	ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &spiSpeed);

	char buffer[0x10];
	buffer[0] = 0x74; // f4 -> MSB must be 0 when writing
	buffer[1] = 0b10110111;
	spiWriteAndRead(fd, buffer, 2, NULL, 0);

	buffer[0] = 0xd0;
	spiWriteAndRead(fd, buffer, 1, buffer, 1);
	printf("ID is %x\n", buffer[0]);

	getchar();

	buffer[0] = 0x88;
	spiWriteAndRead(fd, buffer, 1, buffer, 6);
	dig_T1 = buffer[0] | (buffer[1] << 8);
	dig_T2 = buffer[2] | (buffer[3] << 8);
	dig_T3 = buffer[4] | (buffer[5] << 8);
	printf("dig_T1 is %d\n", dig_T1);
	printf("dig_T2 is %d\n", dig_T2);
	printf("dig T3 is %d\n", dig_T3);

	for (;;) {
		buffer[0] = 0xfa;
		spiWriteAndRead(fd, buffer, 1, buffer, 3);
		int T = (((int)buffer[2] & 0xf0) >> 4) | ((int)buffer[1] << 4) | ((int)buffer[0] << 12);

		printf("SPI Temperature %.2f\n", (float)bmp280_compensate_T_int32(T)/100.0);

		usleep(10000);
	}

	close(fd);

	return 0;	
}