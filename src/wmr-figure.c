// SPDX-FileCopyrightText: 2018-2021 Philipp Zabel <philipp.zabel@gmail.com>
// SPDX-License-Identifier: 0BSD
/*
 * Figure out the Windows Mixed Reality obfuscation key that is XORed onto the
 * JSON calibration information stored in headsets and motion controllers. We
 * need a few obfuscated calibration dumps extracted from real devices and then
 * use a few ideas about how the plaintext should look like to limit the
 * possible key values to as few as possible choices that can then be voted on.
 */
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CONFIG_SIZE 16384

struct sample {
	unsigned char *buf;
	unsigned int start;
	unsigned int size;
};

/*
 * Read an obfuscated configuration blob from a Windows Mixed Reality headset
 * or motion controller into a sample structure.
 */
static int config_read(char *filename, struct sample *sample)
{
	int fd;
	int ret;
	struct stat statbuf;
	unsigned char *buf;
	ssize_t n;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "failed to open \"%s\"\n", filename);
		return -1;
	}

	ret = fstat(fd, &statbuf);
	if (ret == -1) {
		close(fd);
		return -1;
	}

	if (statbuf.st_size > MAX_CONFIG_SIZE)
		return -1;

	buf = malloc(statbuf.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	n = read(fd, buf, statbuf.st_size);
	if (n == -1) {
		free(buf);
		close(fd);
		return -1;
	}

	sample->buf = buf;
	sample->start = buf[0] | (buf[1] << 8);
	sample->size = n - sample->start;

	close(fd);

	return n;
}

/*
 * A few simple rules for JSON objects without whitespace. Limits valid
 * characters given the preceding character.
 */
static inline bool is_valid_char(unsigned char c, unsigned char prev)
{
	/*
	 * Reduce character set to 'a' for lowercase letters, 'A' for uppercase
	 * letters, and '0' for digits.
	 */
	if (c > 'a' && c <= 'z') c = 'a';
	if (c > 'A' && c <= 'Z') c = 'A';
	if (c > '0' && c <= '9') c = '0';
	if (prev > 'a' && prev <= 'z') prev = 'a';
	if (prev > 'A' && prev <= 'Z') prev = 'A';
	if (prev > '0' && prev <= '9') prev = '0';

	/*
	 * The first member of an object must start with a (name) string. Empty
	 * objects are not allowed.
	 */
	if (prev == '{')
		return c == '"';

	/*
	 * An object must be followed by a comma or by the end of the
	 * containing array or object.
	 */
	if (prev == '}')
		return c == ',' || c == ']' || c == '}';

	/*
	 * Allow letters to be followed by other letters, numbers, hyphens,
	 * underscores, whitespace (in strings), or by the end of the string.
	 */
	if (prev == 'a' || prev == 'A')
		return c == 'a' || c == 'A' || c == '0' || c == '-' ||
		       c == '_' || c == ' ' || c == '"';

	/*
	 * Allow digits to be followed by other digits, letters, hyphens,
	 * underscores, whitespace (in strings), or by the end of the string.
	 */
	if (prev == '0')
		return c == '0' || c == 'a' || c == 'A' || c == '.' ||
		       c == ',' || c == '}' || c == ']' || c == ':' ||
		       c == ' ' || c == '"' || c == '/' || c == '-';

	/* Allow commas to be followed by the next object, number, or string */
	if (prev == ',')
		return c == '{' || c == '0' || c == '"' || c == '-';

	/* Allow dots to be followed by the fractional part of a number */
	if (prev == '.')
		return c == '0';

	/*
	 * The first element of an array must be an object, a number, or a
	 * string. Allow empty arrays.
	 */
	if (prev == '[')
		return c == '{' || c == '0' || c == '"' || c == '-' || c == ']';

	/*
	 * An array must be followed by a comma or by the end of the containing
	 * object
	 */
	if (prev == ']')
		return c == ',' || c == '}';

	/*
	 * Colons follow member names and are followed by values: objects,
	 * arrays, strings, or numbers. No booleans or null values.
	 */
	if (prev == ':')
		return c == '{' || c == '[' || c == '"' || c == '-' || c == '0';

	/* Underscores appear in member names, followed by letters or digits */
	if (prev == '_')
		return c == 'A' || c == '0';

	/*
	 * Strings start with uppercase letters or numbers. Member names are
	 * followed by colons, string values are followed by commas, or by the
	 * end of the parent object.
	 */
	if (prev == '"')
		return c == 'A' || c == '0' || c == ':' || c == ',' || c == '}';

	/*
	 * Hyphens appear as signs of negative numbers or in string values
	 * followed by uppercase letters.
	 */
	if (prev == '-')
		return c == '0' || c == 'A';

	/* Slashes are followed by digits, they appear in date string values */
	if (prev == '/')
		return c == '0';

	/*
	 * Whitespace can appear in string values. Followed by uppercase
	 * letters or digits.
	 */
	if (prev == ' ')
		return c == 'A' || c == '0';

	/*
	 * For all other previous characters, return the whole supported
	 * character set.
	 */
	return c == '{' || c == '}' || c == 'a' || c == 'A' || c == '0' ||
	       c == ',' || c == '.' || c == '[' || c == ']' || c == ':' ||
	       c == '_' || c == '"' || c == '/' || c == '-' || c == ' ';
}

/* Print the valid byte value bitfield for byte i of the key */
static void print_valid(int i, uint64_t *valid, int count)
{
	if (count == 1) {
		printf("%4d: \033[32m%016lx %016lx %016lx %016lx\033[m (%u)\n",
		       i, valid[0], valid[1], valid[2], valid[3], count);
	} else {
		printf("%4d: %016lx %016lx %016lx %016lx (%u)\n", i,
		       valid[0], valid[1], valid[2], valid[3], count);
	}
}

static inline bool bit_is_set(uint64_t bitmap[4], uint8_t bit)
{
	return bitmap[bit >> 6] & (1ULL << (bit & 0x3f));
}

static inline void bit_clear(uint64_t bitmap[4], uint8_t bit)
{
	bitmap[bit >> 6] &= ~(1ULL << (bit & 0x3f));
}

static inline uint8_t bit_count(uint64_t bitmap[4])
{
	return __builtin_popcountll(bitmap[0]) +
	       __builtin_popcountll(bitmap[1]) +
	       __builtin_popcountll(bitmap[2]) +
	       __builtin_popcountll(bitmap[3]);
}

/*
 * Return the index with the largest number of votes, or -1.
 */
static int most_votes(int *votes, int count)
{
	int max_votes = 0;
	int vote = -1;
	int i;

	for (i = 0; i < count; i++) {
		if (votes[i] == max_votes)
			vote = -1;
		if (votes[i] > max_votes) {
			max_votes = votes[i];
			vote = i;
		}
	}

	return vote;
}

static inline bool vocal(unsigned char c)
{
	switch (c) {
	case 'A':
	case 'E':
	case 'I':
	case 'O':
	case 'U':
	case 'a':
	case 'e':
	case 'i':
	case 'o':
	case 'u':
		return true;
	default:
		return false;
	}
}

static inline bool consonant(unsigned char c)
{
	if ((c <= 'A' || c > 'Z') && (c <= 'a' || c > 'z'))
		return false;
	return !vocal(c);
}

static inline bool uppercase_consonant(unsigned char c)
{
	if (c <= 'A' || c > 'Z')
		return false;
	return !vocal(c);
}

/*
 * Try to estimate the most likely choice given the previous character, using
 * known properties of CalibrationInformation JSON objects. Compare candidates
 * pairwise and cast a single vote for each candidate that is more likely than
 * the other.
 */
static void cast_votes(unsigned char p, unsigned char *candidate,
		       int *votes, int count)
{
	int i, j;

	if (count < 2)
		return;

	for (i = 0; i < count; i++) {
		for (j = 0; j < count; j++) {
			if (i == j)
				continue;

			if (p == '[' || p == '-' || p == ',') {
				/*
				 * Numbers are much more likely to start with 0 than with any
				 * other digit.
				 */
				if (candidate[i] == '0' &&
				    candidate[j] >= '1' && candidate[j] <= '9')
					votes[i]++;
			}
			if (p == '"') {
				/*
				 * Quotation marks are much more likely to be followed by a
				 * colon (due to member names) than by a digit.
				 */
				if (candidate[i] == ':' &&
				    candidate[j] >= '0' && candidate[j] <= '9')
					votes[i]++;
			}
			if (p >= '0' && p <= '9') {
				/*
				 * Digits are much more likely to be followed
				 * by commas or dots than colons, slashes, or
				 * hyphens, or characters, which only appear in
				 * strings.
				 */
				if ((candidate[i] == ',' || candidate[i] == '.') &&
				    (candidate[j] == ':' || candidate[j] == '/' ||
				     candidate[j] == '-' ||
				     (candidate[j] >= 'A' && candidate[j] <= 'Z') ||
				     (candidate[j] >= 'a' && candidate[j] <= 'z')))
					votes[i]++;
				/*
				 * Digits are much more likely to be followed by other digits
				 * than by colons, which only appear in strings.
				 */
				if (candidate[i] >= '0' && candidate[i] <= '9' &&
				    (candidate[j] == ':'))
					votes[i]++;
				/*
				 * Digits are much more likely to be followed by
				 * a closing parenthesis than by quotation marks.
				 */
				if (candidate[i] == ']' && candidate[j] == '"')
					votes[i]++;
			}
			/* Downgrade consonant sequence at start of word */
			if (uppercase_consonant(p)) {
				if (vocal(candidate[i]) && consonant(candidate[j]))
					votes[i]++;
			}
		}
	}
}

void usage()
{
	fprintf(stderr,
		"Figure out the Windows Mixed Reality obfuscation key that is XORed onto the\n"
		"JSON calibration information stored in headsets and motion controllers.\n"
		"\n"
		"Usage: wmr-figure [OPTIONS] <config1.bin> [<config2.bin> [...]]\n"
		"\n"
		"Options:\n"
		"  -o, --output=FILE    write extracted key to this file\n"
		"  -r, --reference=FILE validate against this reference key\n"
		"  -v, --verbose        increase verbosity (up to 2 times)\n"
		"      --vote           try voting for the most likely option if the key is not well determined\n"
		"  -d, --dump           dump unobfuscated plaintexts\n");
}

int main(int argc, char *argv[])
{
	bool validate;
	struct sample *samples;
	unsigned int num_samples;
	int ret;
	unsigned int i, j, k, l;
	int c;
	unsigned char reference_key[1024];
	static bool enable_votes = true;
	unsigned int verbose = 0;
	char *reference_key_filename = NULL;
	char *output_key_filename = NULL;
	bool dump = false;

	do {
		int option_index = 0;
		static struct option long_options[] = {
			{ "vote", no_argument, 0, 0 },
			{ "verbose", no_argument, 0, 'v' },
			{ "reference", required_argument, 0, 'r' },
			{ "output", required_argument, 0, 'o' },
			{ "dump", no_argument, 0, 'd' },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "do:r:v", long_options, &option_index);
		switch (c) {
		case 0:
			switch (option_index) {
			case 0:
				enable_votes = true;
				break;
			case 1:
				verbose++;
				break;
			case 2:
				reference_key_filename = optarg;
				validate = true;
				break;
			case 3:
				output_key_filename = optarg;
				break;
			case 4:
				dump = true;
				break;
			}
			break;
		case 'd':
			dump = true;
			break;
		case 'o':
			output_key_filename = optarg;
			break;
		case 'r':
			reference_key_filename = optarg;
			validate = true;
			break;
		case 'v':
			verbose++;
			break;
		case -1:
			break;
		default:
			usage();
			exit(1);
		}
	} while (c != -1);

	num_samples = argc - optind;

	if (num_samples < 1) {
		usage();
		exit(1);
	}

	printf("Loading %u samples\n", num_samples);

	samples = calloc(num_samples, sizeof(*samples));
	if (!samples)
		return 1;

	for (i = 0; i < num_samples; i++) {
		ret = config_read(argv[optind + i], &samples[i]);
		if (ret == -1)
			return 1;
	}

	if (validate) {
		/* Read a preexisting key for validation */
		int fd = open(reference_key_filename, O_RDONLY);
		ret = read(fd, reference_key, 1024);
		if (ret != 1024) {
			fprintf(stderr, "Error: failed to read reference key from '%s'\n",
				reference_key_filename);
			return 1;
		}
	}

	/* Keep track of one previous character per 1 KiB block */
	unsigned char (*prev)[16];
	prev = calloc(num_samples, 16);

	/* Possibly byte value bitfield for each key byte (256 bits each) */
	uint64_t (*valid)[4];
	valid = calloc(1024, sizeof(*valid));
	memset(valid, 0xff, 1024 * sizeof(*valid));

	/* For every byte in key */
	for (i = 0; i < 1024; i++) {
		unsigned int count;

		/* For every possible key[i] byte value */
		for (j = 0; j < 256; j++) {
			/* For each obfuscated configuration blob */
			for (l = 0; l < num_samples; l++) {
				struct sample *s = &samples[l];

				/* For every data byte XORed by this key byte */
				for (k = 2 + i; k < s->size; k += 1024) {
					unsigned char c = s->buf[s->start + k] ^ j;
					int index = (k - 2 - i) / 1024;

					/* JSON objects start with '{' */
					if ((k == 2 && c != '{') ||
					    !is_valid_char(c, prev[l][index])) {
						bit_clear(valid[i], j);
						break;
					}
				}
			}
		}

		count = bit_count(valid[i]);

		if (count == 0) {
			print_valid(i, valid[i], count);
			if (validate) {
				fprintf(stderr, "Error: no valid solution at offset %u, reference key = %02x\n", i,
					reference_key[i]);
				for (l = 0; l < num_samples; l++) {
					struct sample *s = &samples[l];

					/* For every data byte XORed by this key byte */
					for (k = 2 + i; k < s->size; k += 1024) {
						unsigned char c = s->buf[s->start + k] ^ reference_key[i];
						int index = (k - 2 - i) / 1024;

						printf((!is_valid_char(c, prev[l][index])) ? "\033[31m%c%c\033[m " : "%c%c ", prev[l][index], c);
					}
				}
				printf("\n");
			} else {
				fprintf(stderr, "Error: no valid solution at offset %u\n", i);
			}
			return 1;
		}

		if (count == 1 && verbose >= 1)
			print_valid(i, valid[i], count);

		if (count > 1) {
			int *votes = calloc(count, sizeof(*votes));
			unsigned char *candidates = malloc(count);
			unsigned int v;
			int winner;

			/* Determine candidates and vote */
			if (enable_votes) {
				for (l = 0; l < num_samples; l++) {
					struct sample *s = &samples[l];

					for (k = 2 + i; k < s->size; k += 1024) {
						int index = (k - 2 - i) / 1024;
						int vote = 0;

						memset(candidates, 0, count);

						for (j = 0; j < 256; j++) {
							unsigned char c;

							if (!bit_is_set(valid[i], j))
								continue;

							c = s->buf[s->start + k] ^ j;

							candidates[vote++] = c;
						}

						cast_votes(prev[l][index], candidates,
							   votes, count);
					}
				}
			}

			winner = most_votes(votes, count);

			if (winner == -1 && verbose >= 2) {
				/* Print candidates */
				for (l = 0; l < num_samples; l++) {
					struct sample *s = &samples[l];

					for (k = 2 + i; k < s->size; k += 1024) {
						int index = (k - 2 - i) / 1024;
						int vote = 0;

						memset(candidates, 0, count);

						printf("\033[34m%c\033[m ", prev[l][index] ? prev[l][index] : ' ');
						for (j = 0; j < 256; j++) {
							unsigned char c;

							if (!bit_is_set(valid[i], j))
								continue;

							c = s->buf[s->start + k] ^ j;

							candidates[vote++] = c;

							printf((validate && j == reference_key[i]) ? "\033[32m%c\033[m " : "%c ", c);
						}
						printf("\n");
					}
				}

				printf("votes: ");
				for (v = 0; v < count; v++)
					printf("%c:%d ", 'A' + v, votes[v]);
				printf(" - %d\n", winner);
			}

			if (winner >= 0) {
				int vote = 0;

				/* Keep only the winning candidate */
				for (j = 0; j < 256; j++) {
					if (!bit_is_set(valid[i], j))
						continue;
					if (vote++ != winner)
						bit_clear(valid[i], j);
				}
				count = 1;
			}

			if (verbose >= 1)
				print_valid(i, valid[i], count);
			free(votes);
		}

		if (count == 1) {
			/*
			 * If a key byte is uniquely identified, determine
			 * previous charactes for the next round.
			 */
			for (j = 0; j < 256; j++) {
				if (!bit_is_set(valid[i], j))
					continue;

				for (l = 0; l < num_samples; l++) {
					struct sample *s = &samples[l];

					for (k = 2 + i; k < s->size; k += 1024) {
						unsigned char c = s->buf[s->start + k] ^ j;
						int index = (k - 2 - i) / 1024;

						prev[l][index] = c;
					}
				}
			}
		} else {
			/* Otherwise clear previous characters. */
			for (l = 0; l < num_samples; l++) {
				for (k = 2 + i; k < samples[l].size; k += 1024) {
					int index = (k - 2 - i) / 1024;

					prev[l][index] = 0;
				}
			}
		}

		/* Optionally verify that the found byte matches the known reference key */
		if (validate && count == 1 && !bit_is_set(valid[i], reference_key[i])) {
			fprintf(stderr, "Error: reference key mismatch at offset %u, reference key = %02x\n", i, reference_key[i]);
			/* For every data byte XORed by this key byte */
			for (l = 0; l < num_samples; l++) {
				struct sample *s = &samples[l];

				for (k = 2 + i; k < s->size; k += 1024) {
					unsigned char c = s->buf[s->start + k] ^ reference_key[i];

					printf((!is_valid_char(c, 0)) ? "\033[31m%c\033[m " : "%c ", c);
				}
				printf("\n");
			}
			return 1;
		}
	}

	/* Extract the key */
	unsigned char extracted_key[1024];
	for (i = 0; i < 1024; i++) {
		int count;

		count = bit_count(valid[i]);
		if (count != 1)
			break;

		for (j = 0; j < 256; j++) {
			if (bit_is_set(valid[i], j))
				extracted_key[i] = j;
		}
	}
	if (i == 1024) {
		printf("Key extracted\n");

		if (output_key_filename) {
			/* Write extracted key */
			int fd = open(output_key_filename, O_RDWR | O_CREAT, 0644);
			ssize_t n;
			if (fd == -1)
				return 1;

			n = write(fd, extracted_key, 1024);
			if (n == -1)
				return 1;

			close(fd);
			printf("Key written to '%s'\n", output_key_filename);
		}
	} else {
		fprintf(stderr, "No key extracted, not enough data?\n");
	}

	if (dump) {
		/* For each obfuscated configuration blob */
		for (l = 0; l < num_samples; l++) {
			struct sample *s = &samples[l];

			printf("\nPlaintext sample %d:\n", l);

			for (i = 0; i < s->size - 2; i++) {
				int k = 2 + i;
				unsigned char c = s->buf[s->start + k] ^ extracted_key[i % 1024];
				int count = bit_count(valid[i % 1024]);

				if (count == 1) {
					printf("%c", c);
				} else {
					/*
					 * If there are still multiple choices,
					 * print them all.
					 */
					printf("\033[1;31m[");
					for (j = 0; j < 256; j++) {
						unsigned char c;

						if (!bit_is_set(valid[i % 1024], j))
							continue;

						c = s->buf[s->start + k] ^ j;
						printf("%c", c);
					}
					printf("]\033[m");
				}
				if (i % 1024 == 1023)
					printf("\n");
			}
			if (i % 1024 != 0)
				printf("\n");
		}
	}

	free(valid);
	free(prev);
	free(samples);

	return 0;
}
