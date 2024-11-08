import { CONFIG } from './config'
import { EncryptionAlgorithm, GenerateProofOpts, GenerateWitnessOpts, Proof, VerifyProofOpts, ZKProofInput } from './types'
import { getCounterForChunk } from './utils'

/**
 * Generate ZK proof for CHACHA20-CTR encryption.
 * Circuit proves that the ciphertext is a
 * valid encryption of the given plaintext.
 * The plaintext can be partially redacted.
 */
export async function generateProof(opts: GenerateProofOpts): Promise<Proof> {
	const { algorithm, operator, logger } = opts
	const { witness, plaintextArray } = await generateZkWitness(opts)
	const wtnsSerialised = await operator.generateWitness(witness)
	const { proof } = await operator.groth16Prove(wtnsSerialised, logger)

	return { algorithm, proofData: proof, plaintext: plaintextArray }
}

/**
 * Generate a ZK witness for the symmetric encryption circuit.
 * This witness can then be used to generate a ZK proof,
 * using the operator's groth16Prove function.
 */
export async function generateZkWitness({
	algorithm,
	privateInput: { key },
	publicInput: { ciphertext, iv, offset },
}: GenerateWitnessOpts,
) {
	const {
		keySizeBytes,
		ivSizeBytes,
	} = CONFIG[algorithm]
	if(key.length !== keySizeBytes) {
		throw new Error(`key must be ${keySizeBytes} bytes`)
	}

	if(iv.length !== ivSizeBytes) {
		throw new Error(`iv must be ${ivSizeBytes} bytes`)
	}

	const startCounter = getCounterForChunk(algorithm, offset)
	const ciphertextArray = padCiphertextToChunkSize(
		algorithm,
		ciphertext,
	)
	const plaintextArray = await decryptCiphertext({
		algorithm,
		key,
		iv,
		offset,
		ciphertext: ciphertextArray,
	})

	const witness: ZKProofInput = {
		key,
		nonce: iv,
		counter: startCounter,
		in: ciphertextArray,
		out: plaintextArray,
	}

	return { witness, plaintextArray }
}

/**
 * Verify a ZK proof for CHACHA20-CTR encryption.
 *
 * @param proofs JSON proof generated by "generateProof"
 * @param publicInput
 * @param zkey
 */
export async function verifyProof({
	proof: { algorithm, proofData, plaintext },
	publicInput: { ciphertext, iv, offset },
	operator,
	logger
}: VerifyProofOpts): Promise<void> {
	const startCounter = getCounterForChunk(algorithm, offset)
	const ciphertextArray = padCiphertextToChunkSize(
		algorithm,
		ciphertext
	)

	if(ciphertextArray.length !== plaintext.length) {
		throw new Error('ciphertext and plaintext must be the same length')
	}

	// serialise to array of numbers for the ZK circuit
	const verified = await operator.groth16Verify(
		{
			nonce: iv,
			counter: startCounter,
			in: ciphertextArray,
			out: plaintext,
		},
		proofData,
		logger
	)

	if(!verified) {
		throw new Error('invalid proof')
	}
}

function padCiphertextToChunkSize(
	alg: EncryptionAlgorithm,
	ciphertext: Uint8Array
) {
	const { chunkSize, bitsPerWord } = CONFIG[alg]

	const expectedSizeBytes = (chunkSize * bitsPerWord) / 8
	if(ciphertext.length > expectedSizeBytes) {
		throw new Error(`ciphertext must be <= ${expectedSizeBytes}b`)
	}

	if(ciphertext.length < expectedSizeBytes) {
		const arr = new Uint8Array(expectedSizeBytes).fill(0)
		arr.set(ciphertext)

		ciphertext = arr
	}

	return ciphertext
}

type DecryptCiphertextOpts = {
	algorithm: EncryptionAlgorithm
	key: Uint8Array
	iv: Uint8Array
	offset: number
	ciphertext: Uint8Array
}

async function decryptCiphertext({
	algorithm,
	key,
	iv,
	offset,
	ciphertext,
}: DecryptCiphertextOpts) {
	const { chunkSize, bitsPerWord, encrypt } = CONFIG[algorithm]
	const chunkSizeBytes = chunkSize * bitsPerWord / 8
	const startOffset = offset * chunkSizeBytes
	const inp = new Uint8Array(startOffset + ciphertext.length)
	inp.set(ciphertext, startOffset)

	const out = await encrypt({ key, iv, in: inp })
	return out.slice(startOffset)
}