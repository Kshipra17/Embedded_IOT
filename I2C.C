#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <linux/i2c-dev.h>
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

int main()
{
	int i2c = open("/dev/i2c-1", O_RDWR);
	ioctl(i2c, I2C_SLAVE, 0x76); // default address
	unsigned char buffer[0x10];
	buffer[0] = 0xf4;
	buffer[1] = 0b10110111;
	write(i2c, buffer, 2);

	buffer[0] = 0xd0;
	write(i2c, buffer, 1);
	read(i2c, buffer, 1);
	printf("ID is %x\n", buffer[0]);

	getchar();

	buffer[0] = 0x88;
	write(i2c, buffer, 1);
	read(i2c, buffer, 6);
	dig_T1 = buffer[0] | (buffer[1] << 8);
	dig_T2 = buffer[2] | (buffer[3] << 8);
	dig_T3 = buffer[4] | (buffer[5] << 8);
	printf("dig_T1 is %d\n", dig_T1);
	printf("dig_T2 is %d\n", dig_T2);
	printf("dig T3 is %d\n", dig_T3);
	for (;;) {
		buffer[0] = 0xfa;
		write(i2c, buffer, 1);
		read(i2c, buffer, 3);
		int T = (((int)buffer[2] & 0xf0) >> 4) | ((int)buffer[1] << 4) | ((int)buffer[0] << 12);

		printf("I2C Temperature %.2f\n", (float)bmp280_compensate_T_int32(T)/100.0);

		usleep(10000);
	}

	close(i2c);

	return 0;
}