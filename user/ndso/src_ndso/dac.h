
#define DAC_RESOLUTION	10
#define REF_VOLTAGE		11
#define MAX_SAMPLERATE	12


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
    CMD_SPI_OUT_ENABLE, 1},	/* AD7476 */
    {
    CMD_SPI_SET_MASTER, 1},
    {
    CMD_SPI_SET_LENGTH16, 1},
    {
    CMD_SPI_MISO_ENABLE, 1},
    {
    CMD_SPI_SET_POLAR, 0},
    {
    CMD_SPI_SET_PHASE, 0},
    {
    CMD_SPI_SET_CSENABLE, 1},
    {
    CMD_SPI_SET_CSLOW, 1},
    {
    CMD_SPI_SET_ORDER, 0},
    {
    0x00, 0x00},
    {
    DAC_RESOLUTION, 4096},	/* 12-Bit (2^12) */
    {
    REF_VOLTAGE, 4096},
    {
  MAX_SAMPLERATE, 1000000}},	/* 1M SPS */
  {
    {
    CMD_SPI_OUT_ENABLE, 1},	/* AD7940 */
    {
    CMD_SPI_SET_MASTER, 1},
    {
    CMD_SPI_SET_LENGTH16, 1},
    {
    CMD_SPI_MISO_ENABLE, 1},
    {
    CMD_SPI_SET_POLAR, 0},
    {
    CMD_SPI_SET_PHASE, 0},
    {
    CMD_SPI_SET_CSENABLE, 1},
    {
    CMD_SPI_SET_CSLOW, 1},
    {
    CMD_SPI_SET_ORDER, 0},
    {
    0x00, 0x00},
    {
    DAC_RESOLUTION, 16384},	/* 14-Bit (2^14) */
    {
    REF_VOLTAGE, 4096},
    {
  MAX_SAMPLERATE, 100000}}	/* 100 kSPS */
};
