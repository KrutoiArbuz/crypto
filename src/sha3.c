/* Собственная реализация SHA3-256: FIPS 202, разделы 3-6 и приложение B.2.
 * Спецификация: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 */
#include "sha3.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(CHAR_BIT == 8, "SHA3 requires 8-bit bytes");

enum { SHA3_RATE = 136, FILE_BUFFER_SIZE = 8192 };

/* Состояние Keccak: A[x,y] хранится в lane[x + 5*y].
 * pos всегда меньше SHA3_RATE, полные блоки обрабатываются сразу.
 */
typedef struct {
    uint64_t lane[25];
    size_t pos;
} Sha3Context;

/*
 * SECURITY: сдвиг на 64 бита в C имеет неопределённое поведение.
 * Отдельная ветка для нуля исключает его; остальные вызовы дают 1..63.
 * Беззнаковый uint64_t исключает проблемы со знаковыми сдвигами.
 */
static uint64_t rotate_left(uint64_t value, unsigned int shift)
{
    return shift == 0 ? value : (value << shift) | (value >> (64U - shift));
}

/* Перестановка Keccak-f[1600]: 24 раунда theta, rho, pi, chi, iota. */
static void keccak_f1600(uint64_t state[25])
{
    static const uint64_t round_constant[24] = {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };
    /* Таблица rho из FIPS 202, приведённая по модулю 64. */
    static const unsigned int rotation[25] = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };
    uint64_t column[5];
    uint64_t mixed[25];

    for (size_t round = 0; round < 24; ++round) {
        /* theta: сумма XOR столбца влияет на два соседних столбца. */
        for (size_t x = 0; x < 5; ++x) {
            column[x] = state[x] ^ state[x + 5] ^ state[x + 10]
                      ^ state[x + 15] ^ state[x + 20];
        }
        for (size_t x = 0; x < 5; ++x) {
            uint64_t delta = column[(x + 4) % 5]
                           ^ rotate_left(column[(x + 1) % 5], 1);
            for (size_t y = 0; y < 5; ++y) {
                state[x + 5 * y] ^= delta;
            }
        }

        /* rho и pi: поворот слова, затем перенос (x,y) в (y,2x+3y). */
        for (size_t y = 0; y < 5; ++y) {
            for (size_t x = 0; x < 5; ++x) {
                size_t index = x + 5 * y;
                mixed[y + 5 * ((2 * x + 3 * y) % 5)] =
                    rotate_left(state[index], rotation[index]);
            }
        }

        /* chi: отдельный массив сохраняет исходные значения строки. */
        for (size_t y = 0; y < 5; ++y) {
            for (size_t x = 0; x < 5; ++x) {
                state[x + 5 * y] = mixed[x + 5 * y]
                    ^ ((~mixed[(x + 1) % 5 + 5 * y])
                       & mixed[(x + 2) % 5 + 5 * y]);
            }
        }

        /* iota: раундовая константа изменяет только A[0,0]. */
        state[0] ^= round_constant[round];
    }
}

/*
 * SECURITY: побайтовая упаковка задаёт little-endian явно, без приведения
 * unsigned char* к uint64_t*. Это исключает нарушение выравнивания,
 * strict aliasing и зависимость результата от порядка байт процессора.
 */
static void absorb(Sha3Context *context, const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        size_t pos = context->pos;
        context->lane[pos / 8] ^= (uint64_t)data[i] << (8U * (pos % 8));
        ++context->pos;
        if (context->pos == SHA3_RATE) {
            keccak_f1600(context->lane);
            context->pos = 0;
        }
    }
}

static void finish(Sha3Context *context,
                   unsigned char digest[SHA3_256_DIGEST_SIZE])
{
    size_t pos = context->pos;

    /* SECURITY: 0x06 включает суффикс SHA-3 и начало pad10*1.
     * Суффикс 0x01 дал бы другой алгоритм (Keccak-256).
     * XOR позволяет совместить 0x06 и 0x80 в 0x86 при pos == 135.
     * При pos == 0 после полного блока добавляется новый блок padding.
     */
    context->lane[pos / 8] ^= UINT64_C(0x06) << (8U * (pos % 8));
    context->lane[(SHA3_RATE - 1) / 8] ^= UINT64_C(0x80)
        << (8U * ((SHA3_RATE - 1) % 8));
    keccak_f1600(context->lane);

    /* 32 байта помещаются в один блок выдачи (136 байт). */
    for (size_t i = 0; i < SHA3_256_DIGEST_SIZE; ++i) {
        digest[i] = (unsigned char)(context->lane[i / 8] >> (8U * (i % 8)));
    }
}

int sha3_256_file(FILE *stream, unsigned char digest[SHA3_256_DIGEST_SIZE])
{
    Sha3Context context = {{0}, 0};
    unsigned char buffer[FILE_BUFFER_SIZE];

    if (stream == NULL || digest == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* SECURITY: фиксированный буфер не зависит от размера входного файла.
     * Нет выделения памяти по недоверенной длине и счётчика общей длины,
     * который мог бы переполниться на очень большом файле.
     */
    for (;;) {
        errno = 0;
        size_t count = fread(buffer, 1, sizeof buffer, stream);

        /* SECURITY: ошибка чтения не должна стать хешем усечённого файла.
         * Проверяется даже частичное чтение; digest ещё не изменён.
         */
        if (ferror(stream)) {
            if (errno == 0) {
                errno = EIO;
            }
            return -1;
        }
        absorb(&context, buffer, count);
        if (feof(stream)) {
            break;
        }
        if (count == 0) {
            errno = EIO;
            return -1;
        }
    }
    finish(&context, digest);
    return 0;
}
