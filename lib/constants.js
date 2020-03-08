const transactionInformationFlags = {
  idMatch: 0x01,
  previousIdMatch: 0x02,
  ipMatch: 0x04,
  sqrlDisabled: 0x08,
  functionNotSupported: 0x10,
  transientError: 0x20,
  commandFailed: 0x40,
  clientFailure: 0x80,
  badIdAssociation: 0x100,
  idSuperseded: 0x200
};

const maxIpLength = 23;
const maxMessageSize = 4096;
const maxNutParamLength = 12;

module.exports = {
  tif: transactionInformationFlags,
  maxIpLength,
  maxMessageSize,
  maxNutParamLength
};
