#ifndef SHA3_H
#define SHA3_H

#include <stdio.h>

enum { SHA3_256_DIGEST_SIZE = 32 };

/*
 * Вычисляет SHA3-256 от текущей позиции файла до EOF по FIPS 202.
 * stream должен быть открыт для бинарного чтения; функция его не закрывает.
 * digest должен указывать на массив минимум из SHA3_256_DIGEST_SIZE байт.
 * Возвращает 0 при успехе, -1 при ошибке (errno содержит причину).
 * При ошибке digest не изменяется, хеш неполного файла не возвращается.
 */
int sha3_256_file(FILE *stream, unsigned char digest[SHA3_256_DIGEST_SIZE]);

#endif
