import * as zlib from 'zlib';
import { zipSync, unzipSync, deflateSync, inflateSync } from 'fflate';

export class DataCompressor {
    static compress(data: Uint8Array, algorithm: string = 'zip', fileName?: string): Uint8Array {
        switch (algorithm) {
            case 'zlib':
                return zlib.gzipSync(data);
            case 'zip':
                if (fileName) {
                    const zipData = zipSync({ [fileName]: data });
                    return zipData;
                } else {
                    return deflateSync(data);
                }
            default:
                throw new Error('Unsupported algorithm');
        }
    }

    static uncompress(data: Uint8Array, algorithm: string = 'zip'): Uint8Array {
        switch (algorithm) {
            case 'zlib':
                return zlib.gunzipSync(data);
            case 'zip':
                const isZipFormat = data.length >= 2 && data[0] === 0x50 && data[1] === 0x4B;
                if (isZipFormat) {
                    try {
                        const unzipped = unzipSync(data);
                        const firstFileName = Object.keys(unzipped)[0];
                        if (firstFileName) {
                            return unzipped[firstFileName];
                        }
                        throw new Error('ZIP archive is empty');
                    } catch (error) {
                        throw new Error('Data is not in valid ZIP format');
                    }
                }
                const mightBeDeflate = data.length >= 2 &&
                    data[0] === 0x78 &&
                    (data[1] === 0x9C || data[1] === 0xDA || data[1] === 0x01);
                if (!mightBeDeflate) {
                    throw new Error('Data is not in ZIP or DEFLATE format');
                }
                try {
                    const decompressed = inflateSync(data);
                    if (decompressed.length >= data.length) {
                        throw new Error('Data does not appear to be compressed');
                    }
                    return decompressed;
                } catch (error) {
                    throw new Error('Data is not in ZIP or DEFLATE format');
                }
            default:
                throw new Error('Unsupported algorithm');
        }
    }
}
