package it.xaos.algorand.first

import com.algorand.algosdk.account.Account
import com.algorand.algosdk.crypto.Address
import com.algorand.algosdk.kmd.client.ApiException
import com.algorand.algosdk.kmd.client.KmdClient
import com.algorand.algosdk.kmd.client.api.KmdApi
import com.algorand.algosdk.kmd.client.model.*
import com.algorand.algosdk.transaction.SignedTransaction
import com.algorand.algosdk.transaction.Transaction
import com.algorand.algosdk.util.Encoder
import com.algorand.algosdk.v2.client.common.AlgodClient
import com.algorand.algosdk.v2.client.common.IndexerClient
import java.io.IOException
import java.lang.Exception
import java.security.NoSuchAlgorithmException
import java.util.*


object Application {
    private const val token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private var kmd: KmdApi? = null
    @Throws(Exception::class)
    @JvmStatic
    fun main(args: Array<String>) {
        // Initialize algod/indexer v2 clients.
        val algod = AlgodClient("http://localhost", 4001, token)
        val indexer = IndexerClient("http://localhost", 8980)

        // Initialize KMD v1 client
        val kmdClient = KmdClient()
        kmdClient.basePath = "http://localhost:4002"
        kmdClient.setApiKey(token)
        kmd = KmdApi(kmdClient)

        // Get accounts from sandbox.
        val walletHandle = defaultWalletHandle
        val accounts = getWalletAccounts(walletHandle)

        // Create a payment transaction
        val tx1 = Transaction.PaymentTransactionBuilder()
            .lookupParams(algod) // lookup fee, firstValid, lastValid
            .sender(accounts[0])
            .receiver(accounts[1])
            .amount(1000000)
            .noteUTF8("test transaction!")
            .build()

        // Sign with KMD
        val stx1a = signTransactionWithKMD(tx1, walletHandle)
        val stx1aBytes = Encoder.encodeToMsgPack(stx1a)

        // Sign with private key
        val privateKey = lookupPrivateKey(accounts[0], walletHandle)
        val account = Account(privateKey)
        val stx1b = account.signTransaction(tx1)
        val stx1bBytes = Encoder.encodeToMsgPack(stx1b)

        // KMD and signing directly should both be the same.
        if (!Arrays.equals(stx1aBytes, stx1bBytes)) {
            throw RuntimeException("KMD disagrees with the manual signature!")
        }

        // Send transaction
        val post = algod.RawTransaction().rawtxn(stx1aBytes).execute()
        if (!post.isSuccessful) {
            throw RuntimeException("Failed to post transaction")
        }

        // Wait for confirmation
        var done = false
        while (!done) {
            val txInfo = algod.PendingTransactionInformation(post.body().txId).execute()
            if (!txInfo.isSuccessful) {
                throw RuntimeException("Failed to check on tx progress")
            }
            if (txInfo.body().confirmedRound != null) {
                done = true
            }
        }

        // Wait for indexer to index the round.
        Thread.sleep(5000)

        // Query indexer for the transaction
        val transactions = indexer.searchForTransactions()
            .txid(post.body().txId)
            .execute()
        if (!transactions.isSuccessful) {
            throw RuntimeException("Failed to lookup transaction")
        }
        println("Transaction received! \n$transactions")
    }

    @Throws(IOException::class, ApiException::class)
    fun signTransactionWithKMD(tx: Transaction?, walletHandle: String?): SignedTransaction {
        val req = SignTransactionRequest()
        req.transaction(Encoder.encodeToMsgPack(tx))
        req.walletHandleToken = walletHandle
        req.walletPassword = ""
        val stxBytes = kmd!!.signTransaction(req).signedTransaction
        return Encoder.decodeFromMsgPack(stxBytes, SignedTransaction::class.java)
    }

    @Throws(ApiException::class)
    fun lookupPrivateKey(addr: Address, walletHandle: String?): ByteArray {
        val req = ExportKeyRequest()
        req.address = addr.toString()
        req.walletHandleToken = walletHandle
        req.walletPassword = ""
        return kmd!!.exportKey(req).privateKey
    }

    @get:Throws(ApiException::class)
    val defaultWalletHandle: String
        get() {
            for (w in kmd!!.listWallets().wallets) {
                if (w.name == "unencrypted-default-wallet") {
                    val tokenreq = InitWalletHandleTokenRequest()
                    tokenreq.walletId = w.id
                    tokenreq.walletPassword = ""
                    return kmd!!.initWalletHandleToken(tokenreq).walletHandleToken
                }
            }
            throw RuntimeException("Default wallet not found.")
        }

    @Throws(ApiException::class, NoSuchAlgorithmException::class)
    fun getWalletAccounts(walletHandle: String?): List<Address> {
        val accounts: MutableList<Address> = ArrayList()
        val keysRequest = ListKeysRequest()
        keysRequest.walletHandleToken = walletHandle
        for (addr in kmd!!.listKeysInWallet(keysRequest).addresses) {
            accounts.add(Address(addr))
        }
        return accounts
    }
}