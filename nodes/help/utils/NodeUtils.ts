import { IExecuteFunctions, NodeOperationError } from 'n8n-workflow';

class NodeUtils {
	/**
	 * Get binary data buffer and metadata (handles both Base64 and S3 storage)
	 * @param this - IExecuteFunctions context
	 * @param itemIndex - Item index
	 * @param binaryPropertyName - Binary property name
	 */
	static async getBinaryData(
		this: IExecuteFunctions,
		itemIndex: number,
		binaryPropertyName: string,
	) {
		const binaryData = this.helpers.assertBinaryData(itemIndex, binaryPropertyName);
		if (!binaryData) {
			throw new NodeOperationError(
				this.getNode(),
				`Binary data is not available in property "${binaryPropertyName}".`,
			);
		}

		const buffer = await this.helpers.getBinaryDataBuffer(itemIndex, binaryPropertyName);
		const data = new Uint8Array(buffer);

		return {
			value: buffer,
			data: data,
			options: {
				filename: binaryData.fileName,
				filelength: binaryData.fileSize,
				contentType: binaryData.mimeType,
			},
		};
	}

	/**
	 * Get signature binary data as string (handles both Base64 and S3 storage)
	 * @param this - IExecuteFunctions context
	 * @param itemIndex - Item index
	 * @param binaryPropertyName - Binary property name for signature
	 */
	static async getSignatureData(
		this: IExecuteFunctions,
		itemIndex: number,
		binaryPropertyName: string,
	) {
		const binaryData = this.helpers.assertBinaryData(itemIndex, binaryPropertyName);
		if (!binaryData) {
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
