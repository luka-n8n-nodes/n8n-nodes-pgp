import { IExecuteFunctions, NodeOperationError } from 'n8n-workflow';

class NodeUtils {
	/**
	 * Get binary data buffer and metadata (handles both Base64 and S3 storage)
	 * @param this - IExecuteFunctions context
	 * @param itemIndex - Item index
	 * @param binaryPropertyName - Binary property name
	 * @returns Object containing buffer, metadata (fileName, fileSize, mimeType), and Uint8Array
	 */
	static async getBinaryData(
		this: IExecuteFunctions,
		itemIndex: number,
		binaryPropertyName: string,
	): Promise<{
		buffer: Buffer;
		meta: {
			fileName?: string;
			fileSize?: number;
			mimeType?: string;
		};
		data: Uint8Array;
	}> {
		const binaryDataMeta = this.helpers.assertBinaryData(itemIndex, binaryPropertyName);
		if (!binaryDataMeta) {
			throw new NodeOperationError(
				this.getNode(),
				`Binary data is not available in property "${binaryPropertyName}".`,
			);
		}

		const buffer = await this.helpers.getBinaryDataBuffer(itemIndex, binaryPropertyName);
		const data = new Uint8Array(buffer);

		return {
			buffer,
			meta: {
				fileName: binaryDataMeta.fileName,
				fileSize: binaryDataMeta.fileSize as number | undefined,
				mimeType: binaryDataMeta.mimeType,
			},
			data,
		};
	}

	/**
	 * Get signature binary data as string (handles both Base64 and S3 storage)
	 * @param this - IExecuteFunctions context
	 * @param itemIndex - Item index
	 * @param binaryPropertyName - Binary property name for signature
	 * @returns Signature string
	 */
	static async getSignatureData(
		this: IExecuteFunctions,
		itemIndex: number,
		binaryPropertyName: string,
	): Promise<string> {
		const signatureDataMeta = this.helpers.assertBinaryData(itemIndex, binaryPropertyName);
		if (!signatureDataMeta) {
			throw new NodeOperationError(
				this.getNode(),
				`Signature binary data is not available in property "${binaryPropertyName}".`,
			);
		}

		const buffer = await this.helpers.getBinaryDataBuffer(itemIndex, binaryPropertyName);
		return buffer.toString('utf-8');
	}
}

export default NodeUtils;
