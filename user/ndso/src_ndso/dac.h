
#define DAC_RESOLUTION	0
#define REF_VOLTAGE	1
#define MAX_SAMPLERATE	2


enum
{
  AD7476, AD7940
};


struct
{
  unsigned int cmd, arg;
}
hw_device_table[][13] =
{
  {
    {
    DAC_RESOLUTION, 4096},	/* 12-Bit (2^12) */
    {
    REF_VOLTAGE, 4096},
    {
    MAX_SAMPLERATE, 1000000}},	/* 1M SPS */
  {
    {
    DAC_RESOLUTION, 16384},	/* 14-Bit (2^14) */
    {
    REF_VOLTAGE, 4096},
    {
    MAX_SAMPLERATE, 100000}}	/* 100 kSPS */
};
