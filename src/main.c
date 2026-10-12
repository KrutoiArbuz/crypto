#include "sha3.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SECURITY: управляющие символы в имени файла могут подделать строки
 * вывода или отправить команды терминалу. Печатаем их в видимом виде.
 * Форматная строка всегда фиксирована: имя не интерпретируется как формат.
 */
static void print_path(FILE *output, const char *path)
{
    const unsigned char *p = (const unsigned char *)path;

    for (; *p != '\0'; ++p) {
        switch (*p) {
        case '\\': fputs("\\\\", output); break;
        case '\n': fputs("\\n", output); break;
        case '\r': fputs("\\r", output); break;
        case '\t': fputs("\\t", output); break;
        default:
            if (*p < 32 || *p == 127) {
                fprintf(output, "\\x%02x", (unsigned int)*p);
            } else {
                fputc(*p, output);
            }
            break;
        }
    }
}

static void report_error(const char *action, const char *path, int error)
{
    fprintf(stderr, "sha3sum: %s '", action);
    print_path(stderr, path);
    fprintf(stderr, "': %s\n", strerror(error));
}

int main(int argc, char *argv[])
{
    unsigned char digest[SHA3_256_DIGEST_SIZE];

    if (argc != 2) {
        fputs("Usage: sha3sum FILE\nComputes SHA3-256 of a file.\n", stderr);
        return EXIT_FAILURE;
    }

    /* Бинарный режим сохраняет все байты, включая NUL и переводы строк. */
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) {
        report_error("cannot open", argv[1], errno);
        return EXIT_FAILURE;
    }

    if (sha3_256_file(input, digest) != 0) {
        int error = errno; /* fclose может изменить errno. */
        (void)fclose(input);
        report_error("cannot read", argv[1], error);
        return EXIT_FAILURE;
    }
    if (fclose(input) != 0) {
        report_error("cannot close", argv[1], errno);
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < SHA3_256_DIGEST_SIZE; ++i) {
        printf("%02x", (unsigned int)digest[i]);
    }
    fputs("  ", stdout);
    print_path(stdout, argv[1]);
    fputc('\n', stdout);

    /* SECURITY: ошибка записи не должна приводить к успешному коду выхода.
     * fflush обнаруживает и ошибки отложенной записи буферизованного stdout.
     */
    if (fflush(stdout) == EOF || ferror(stdout)) {
        fputs("sha3sum: cannot write output\n", stderr);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
