#ifndef BITCOIN_INTERPRETER_HPP
#define BITCOIN_INTERPRETER_HPP

#include "arcmist/base/log.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"
#include "key.hpp"

#include <list>

#define BITCOIN_INTERPRETER_LOG_NAME "BitCoin Transaction"


namespace BitCoin
{
    enum ScriptType
    {
        UNKNOWN,
        P2PKH,     // secp256k1 signature and sha256(ripemd160()) hash of secp256k1 public key
        P2SH,      // sha256(ripemd160()) hash of redeem script
        /* TODO Check support for multisig P2SH
         * pub key script : OP_HASH160 <Hash160(redeemScript)> OP_EQUAL
         * redeem script : <OP_2> <A pubkey> <B pubkey> <C pubkey> <OP_3> OP_CHECKMULTISIG
         * sig script : OP_0 <A sig> <C sig> <redeemScript> */
        MULTI_SIG, //TODO
        /* pub key script :  <m> <A pubkey> [B pubkey] [C pubkey...] <n> OP_CHECKMULTISIG
         * sig script : OP_0 <A sig> [B sig] [C sig...] */
        P2PK,      //TODO pub key script : <pubkey> OP_CHECKSIG, sig script : <sig>
        NULL_DATA  //TODO pub key script : OP_RETURN <0-80 bytes of data>, sig script : (can't be spent)
    };

    // Parse output script for hash/address
    ScriptType parseOutputScript(ArcMist::Buffer &pScript, Hash &pHash);

    // Create a P2PKH (Pay to Public Key Hash) signature script
    bool writeP2PKHSignatureScript(const PrivateKey      &pPrivateKey,
                                   const PublicKey       &pPublicKey,
                                   ArcMist::Buffer       &pScript,
                                   ArcMist::OutputStream *pOutput);

    // Create a P2PKH (Pay to Public Key Hash) public key/output script
    void writeP2PKHPublicKeyScript(const Hash &pPublicKeyHash, ArcMist::OutputStream *pOutput);

    // Create a P2SH (Pay to Script Hash) signature script
    void writeP2SHSignatureScript(ArcMist::Buffer &pRedeemScript, ArcMist::OutputStream *pOutput);

    // Create a P2SH (Pay to Script Hash) multi signature script
    void addSignatureToP2SHMultiSignatureScript(const PrivateKey &pPrivateKey,
                                                const PublicKey  &pPublicKey,
                                                ArcMist::Buffer  &pRedeemScript,
                                                ArcMist::Buffer  &pSignatureScript);

    // Create a P2SH (Pay to Script Hash) public key/output script
    void writeP2SHPublicKeyScript(const Hash &pScriptHash, ArcMist::OutputStream *pOutput);

    // Write to a script to push the following size of data to the stack
    void writePushDataSize(unsigned int pSize, ArcMist::OutputStream *pOutput);
    
    void writeScriptToText(ArcMist::InputStream *pScript, ArcMist::OutputStream *pText);

    inline bool bufferIsZero(ArcMist::Buffer &pBuffer)
    {
        while(pBuffer.remaining() > 0)
            if(pBuffer.readByte() != 0)
                return false;
        return true;
    }

    class ScriptInterpreter
    {
    public:

        ScriptInterpreter() { mValid = true; mVerified = false; }
        ~ScriptInterpreter() { clear(); }

        // Process script
        bool process(ArcMist::Buffer &pScript);

        // No issues processing script
        bool isValid()
        {
            if(!mValid)
                return false;

            if(mIfStack.size() > 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Not all if statements ended : %d", mIfStack.size());
                return false;;
            }

            return true;
        }

        // Script verifies and signatures were all correct
        bool isVerified()
        {
            if(!mVerified)
                return false;

            // Valid if top stack item is not zero
            if(mStack.size() > 0)
            {
                top()->setReadOffset(0);
                if(bufferIsZero(*top()))
                    return false; // Top stack item is zero
                else
                    return true; // Top stack item is not zero
            }
            else
                return false; // Empty stack
        }

        void clear()
        {
            mValid = true;
            mVerified = false;

            std::list<ArcMist::Buffer *>::iterator iter;

            for(iter=mStack.begin();iter!=mStack.end();++iter)
                delete *iter;
            mStack.clear();

            for(iter=mAltStack.begin();iter!=mAltStack.end();++iter)
                delete *iter;
            mAltStack.clear();
            
            mIfStack.clear();
            mAltIfStack.clear();
        }

        // For debugging
        void printStack(const char *pText)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "%d items on the stack : %s", mStack.size(), pText);

            unsigned int index = 1;
            for(std::list<ArcMist::Buffer *>::iterator i = mStack.begin();i!=mStack.end();++i,index++)
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                  "   Item %d has %d bytes", index, (*i)->length());
        }

    private:

        bool mValid;
        bool mVerified;
        Hash mHash;

        std::list<ArcMist::Buffer *> mStack, mAltStack;
        std::list<bool> mIfStack, mAltIfStack;

        bool ifStackTrue()
        {
            if(mIfStack.size() == 0)
                return true;

            std::list<bool>::iterator i = mIfStack.begin();
            while(i != mIfStack.end())
                if(!(*i))
                    return false;

            return true;
        }

        bool checkStackSize(unsigned int pMinimum) { return mStack.size() >= pMinimum; }
        bool checkAltStackSize(unsigned int pMinimum) { return mAltStack.size() >= pMinimum; }

        unsigned int popInteger()
        {
            ArcMist::Buffer *buffer = top();
            unsigned int result = 0;
            buffer->setReadOffset(0);
            if(buffer->length() == 1)
                result = buffer->readByte();
            else if(buffer->length() == 2)
                result = buffer->readUnsignedShort();
            else if(buffer->length() == 4)
                result = buffer->readUnsignedInt();
            pop();
            return result;
        }

        // Stack manipulation
        ArcMist::Buffer *push() { mStack.push_back(new ArcMist::Buffer()); return mStack.back(); }
        void push(ArcMist::Buffer *pValue) { mStack.push_back(pValue); }
        void pop(bool pDelete = true) { if(pDelete) delete mStack.back(); mStack.pop_back(); }
        ArcMist::Buffer *top() { return mStack.back(); }
        bool stackIsEmpty() { return mStack.size() == 0; }

        // Alt Stack manipulation
        ArcMist::Buffer *pushAlt() { mAltStack.push_back(new ArcMist::Buffer()); return mAltStack.back(); }
        void pushAlt(ArcMist::Buffer *pValue) { mAltStack.push_back(pValue); }
        void popAlt(bool pDelete = true) { if(pDelete) delete mAltStack.back(); mAltStack.pop_back(); }
        ArcMist::Buffer *topAlt() { return mAltStack.back(); }
        bool stackAltIsEmpty() { return mAltStack.size() == 0; }

    };
}

#endif
