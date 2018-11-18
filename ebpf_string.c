#ifndef EBPF_STRING
#define EBPF_STRING

#define LENGTH_MAX 16

static int ebpf_strlen(char* s) {
  #pragma unroll(LENGTH_MAX)
  for (int i = 0; i < LENGTH_MAX; i++) {
    if (s[i] == '\0') {
      return i;
    };
  }
  return LENGTH_MAX;
}

static void ebpf_strcat(char* dst, char* src) {
  int srclen = ebpf_strlen(src);
  int dstlen = ebpf_strlen(dst);

  if (srclen + dstlen >= sizeof(dst)) return;

  dst[dstlen] = '/';
  memcpy(dst + dstlen + 1, src, LENGTH_MAX);
}

static void ebpf_strcpy(char* dst, char* src) {
  int srclen = ebpf_strlen(src);
  memcpy(dst, src, srclen);
}

static int ebpf_strcmp(char *buff1, char *buff2) {
  #pragma unroll (LENGTH_MAX)
  for (int i = 1; i <= LENGTH_MAX; i++) {
    if (buff1[i-1] != buff2[i-1]) {
      return i;
    };
  }
  return 0;
}

#endif