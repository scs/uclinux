
#define DAC_RESOLUTION	10
#define REF_VOLTAGE		11
#define MAX_SAMPLERATE	12


enum
{
  AD5443, ADxxxx
};


struct
{
  unsigned int cmd, arg;
}
hw_device_table[][4] =
{
  {/* AD5443 */
    {
    0x00, 0x00},
    {
    DAC_RESOLUTION, 4096},	/* 12-Bit (2^12) */
    {
    REF_VOLTAGE, 4096},
    {
  MAX_SAMPLERATE, 25000000}},	/* 1M SPS */
  {/* ADxxxx */
    {
    0x00, 0x00},
    {
    DAC_RESOLUTION, 4096},	/* 12-Bit (2^12) */
    {
    REF_VOLTAGE, 4096},
    {
  MAX_SAMPLERATE, 100000}}	/* 100 kSPS */
};
