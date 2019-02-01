/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_INTERPRETER_HPP
#define BITCOIN_INTERPRETER_HPP

#include "hash.hpp"
#include "log.hpp"
#include "buffer.hpp"
#include "base.hpp"
#include "key.hpp"
#include "forks.hpp"
#include "transaction.hpp"

#include <list>

#define BITCOIN_INTERPRETER_LOG_NAME "Interpreter"


namespace BitCoin
{
    static const uint8_t MAX_SINGLE_BYTE_PUSH_DATA_CODE = 0x4b;

    enum OperationCodes
    {
        OP_0                   = 0x00, // An empty array of bytes is pushed to the stack
        OP_FALSE               = 0x00, // An empty array of bytes is pushed to the stack

        OP_PUSHDATA1           = 0x4c, // The next byte contains the number of bytes to be pushed
        OP_PUSHDATA2           = 0x4d, // The next 2 bytes contains the number of bytes to be pushed
        OP_PUSHDATA4           = 0x4e, // The next 4 bytes contains the number of bytes to be pushed

        OP_1NEGATE             = 0x4f, // The number -1 is pushed
        OP_1                   = 0x51, // The number 1 is pushed
        OP_TRUE                = 0x51, // The number 1 is pushed
        OP_2                   = 0x52, // The number 2 is pushed
        OP_3                   = 0x53, // The number 3 is pushed
        OP_4                   = 0x54, // The number 4 is pushed
        OP_5                   = 0x55, // The number 5 is pushed
        OP_6                   = 0x56, // The number 6 is pushed
        OP_7                   = 0x57, // The number 7 is pushed
        OP_8                   = 0x58, // The number 8 is pushed
        OP_9                   = 0x59, // The number 9 is pushed
        OP_10                  = 0x5a, // The number 10 is pushed
        OP_11                  = 0x5b, // The number 11 is pushed
        OP_12                  = 0x5c, // The number 12 is pushed
        OP_13                  = 0x5d, // The number 13 is pushed
        OP_14                  = 0x5e, // The number 14 is pushed
        OP_15                  = 0x5f, // The number 15 is pushed
        OP_16                  = 0x60, // The number 16 is pushed

        OP_NOP                 = 0x61, // Does nothing
        OP_IF                  = 0x63, // If the top stack value is not OP_FALSE the statements are executed. The top stack value is removed
        OP_NOTIF               = 0x64, // If the top stack value is OP_FALSE the statements are executed. The top stack value is removed
        OP_ELSE                = 0x67, // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
        OP_ENDIF               = 0x68, // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.

        OP_VERIFY              = 0x69, // Marks transaction as invalid if top stack value is not true.
        OP_RETURN              = 0x6a, // Marks transaction as invalid

        OP_EQUAL               = 0x87, // Returns 1 if the inputs are exactly equal, 0 otherwise
        OP_EQUALVERIFY         = 0x88, // Same as OP_EQUAL, but runs OP_VERIFY afterward.


        // Hashes
        OP_RIPEMD160           = 0xa6, // in   hash   The input is hashed using RIPEMD-160.
        OP_SHA1                = 0xa7, // in  hash  The input is hashed using SHA-1.
        OP_SHA256              = 0xa8, // in  hash  The input is hashed using SHA-256.
        OP_HASH160             = 0xa9, // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        OP_HASH256             = 0xaa, // The input is hashed two times with SHA-256.


        // Signatures
        OP_CODESEPARATOR       = 0xab, // All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.

        OP_CHECKSIG            = 0xac,
        /* The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR
         *   to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and
         *   public key. If it is, 1 is returned, 0 otherwise. */
        OP_CHECKSIGVERIFY      = 0xad, // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.

        OP_CHECKMULTISIG       = 0xae,
        /* Compares the first signature against each public key until it finds an ECDSA match. Starting with the
         *   subsequent public key, it compares the second signature against each remaining public key until it
         *   finds an ECDSA match. The process is repeated until all signatures have been checked or not enough
         *   public keys remain to produce a successful result. All signatures need to match a public key. Because
         *   public keys are not checked again if they fail any signature comparison, signatures must be placed in
         *   the scriptSig using the same order as their corresponding public keys were placed in the scriptPubKey
         *   or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise. Due to a bug, one extra
         *   unused value is removed from the stack.
         *
         * Preceding data
         *   <extra value to be removed by bug> sig1 sig2 ... <number of signatures> pub1 pub2 <number of public keys>
         */
        OP_CHECKMULTISIGVERIFY = 0xaf, // Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        /* Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime field,
         *   otherwise script evaluation continues as though an OP_NOP was executed. Transaction is also invalid
         *   if 1. the stack is empty; or 2. the top stack item is negative; or 3. the top stack item is greater
         *   than or equal to 500000000 while the transaction's nLockTime field is less than 500000000, or vice
         *   versa; or 4. the input's nSequence field is equal to 0xffffffff. The precise semantics are described
         *   in BIP 0065 */
        OP_CHECKSEQUENCEVERIFY  = 0xb2,
        /* Marks transaction as invalid if the relative lock time of the input (enforced by BIP 0068 with nSequence)
         * is not equal to or longer than the value of the top stack item. The precise semantics are described in BIP 0112. */

        OP_1ADD                = 0x8b, //    in    out    1 is added to the input.
        OP_1SUB                = 0x8c, //    in    out    1 is subtracted from the input.
        OP_2MUL                = 0x8d, //    in    out    The input is multiplied by 2. disabled.
        OP_2DIV                = 0x8e, //    in    out    The input is divided by 2. disabled.
        OP_NEGATE              = 0x8f, //    in    out    The sign of the input is flipped.
        OP_ABS                 = 0x90, //    in    out    The input is made positive.
        OP_NOT                 = 0x91, //    in    out    If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
        OP_0NOTEQUAL           = 0x92, //    in    out    Returns 0 if the input is 0. 1 otherwise.
        OP_ADD                 = 0x93, //    a b   out    a is added to b.
        OP_SUB                 = 0x94, //    a b   out    b is subtracted from a.
        OP_MUL                 = 0x95, //    a b   out    a is multiplied by b. disabled.
        OP_DIV                 = 0x96, //    a b   out    a is divided by b. disabled.
        OP_MOD                 = 0x97, //    a b   out    Returns the remainder after dividing a by b. disabled.
        OP_LSHIFT              = 0x98, //    a b   out    Shifts a left b bits, preserving sign. disabled.
        OP_RSHIFT              = 0x99, //    a b   out    Shifts a right b bits, preserving sign. disabled.
        OP_BOOLAND             = 0x9a, //    a b   out    If both a and b are not 0, the output is 1. Otherwise 0.
        OP_BOOLOR              = 0x9b, //    a b   out    If a or b is not 0, the output is 1. Otherwise 0.
        OP_NUMEQUAL            = 0x9c, //    a b   out    Returns 1 if the numbers are equal, 0 otherwise.
        OP_NUMEQUALVERIFY      = 0x9d, //    a b   Nothing / fail    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
        OP_NUMNOTEQUAL         = 0x9e, //    a b   out    Returns 1 if the numbers are not equal, 0 otherwise.
        OP_LESSTHAN            = 0x9f, //    a b   out    Returns 1 if a is less than b, 0 otherwise.
        OP_GREATERTHAN         = 0xa0, //    a b   out    Returns 1 if a is greater than b, 0 otherwise.
        OP_LESSTHANOREQUAL     = 0xa1, //    a b   out    Returns 1 if a is less than or equal to b, 0 otherwise.
        OP_GREATERTHANOREQUAL  = 0xa2, //    a b   out    Returns 1 if a is greater than or equal to b, 0 otherwise.
        OP_MIN                 = 0xa3, //    a b   out    Returns the smaller of a and b.
        OP_MAX                 = 0xa4, //    a b   out    Returns the larger of a and b.
        OP_WITHIN              = 0xa5, //    x min max    out    Returns 1 if x is within the specified range (left-inclusive), 0 otherwise

        // Stack
        OP_TOALTSTACK          = 0x6b, // Puts the input onto the top of the alt stack. Removes it from the main stack.
        OP_FROMALTSTACK        = 0x6c, // Puts the input onto the top of the main stack. Removes it from the alt stack.
        OP_IFDUP               = 0x73, //     x    x / x x    If the top stack value is not 0, duplicate it.
        OP_DEPTH               = 0x74, //     Nothing    <Stack size>    Puts the number of stack items onto the stack.
        OP_DROP                = 0x75, //     x    Nothing    Removes the top stack item.
        OP_DUP                 = 0x76, //     x    x x    Duplicates the top stack item.
        OP_NIP                 = 0x77, //     x1 x2    x2    Removes the second-to-top stack item.
        OP_OVER                = 0x78, //     x1 x2    x1 x2 x1    Copies the second-to-top stack item to the top.
        OP_PICK                = 0x79, //     xn ... x2 x1 x0 <n>    xn ... x2 x1 x0 xn    The item n back in the stack is copied to the top.
        OP_ROLL                = 0x7a, //     xn ... x2 x1 x0 <n>    ... x2 x1 x0 xn    The item n back in the stack is moved to the top.
        OP_ROT                 = 0x7b, //     x1 x2 x3    x2 x3 x1    The top three items on the stack are rotated to the left.
        OP_SWAP                = 0x7c, //     x1 x2    x2 x1    The top two items on the stack are swapped.
        OP_TUCK                = 0x7d, //     x1 x2    x2 x1 x2    The item at the top of the stack is copied and inserted before the second-to-top item.
        OP_2DROP               = 0x6d, //     x1 x2    Nothing    Removes the top two stack items.
        OP_2DUP                = 0x6e, //     x1 x2    x1 x2 x1 x2    Duplicates the top two stack items.
        OP_3DUP                = 0x6f, //     x1 x2 x3    x1 x2 x3 x1 x2 x3    Duplicates the top three stack items.
        OP_2OVER               = 0x70, //     x1 x2 x3 x4    x1 x2 x3 x4 x1 x2    Copies the pair of items two spaces back in the stack to the front.
        OP_2ROT                = 0x71, //     x1 x2 x3 x4 x5 x6    x3 x4 x5 x6 x1 x2    The fifth and sixth items back are moved to the top of the stack.
        OP_2SWAP               = 0x72, //     x1 x2 x3 x4    x3 x4 x1 x2	Swaps the top two pairs of items.


        // Splice
        OP_CAT                 = 0x7e, //  x1 x2  out  Concatenates two strings. disabled.
        // OP_SUBSTR, OP_LEFT, and OP_RIGHT are being replaced by OP_SPLIT, OP_NUM2BIN. and OP_BIN2NUM
        //OP_SUBSTR              = 0x7f, //  in begin size  out  Returns a section of a string. disabled.
        //OP_LEFT                = 0x80, //  in size  out  Keeps only characters left of the specified point in a string. disabled.
        //OP_RIGHT               = 0x81, //  in size  out  Keeps only characters right of the specified point in a string. disabled.
        OP_SPLIT               = 0x7f, // Split byte sequence x at position n
        OP_NUM2BIN             = 0x80, // Convert numeric value a into byte sequence of length b
        OP_BIN2NUM             = 0x81, // Convert byte sequence x into a numeric value
        OP_SIZE                = 0x82, //  in  in size  Pushes the string length of the top element of the stack (without popping it).


        // Bitwise logic
        OP_INVERT              = 0x83, //  in  out  Flips all of the bits in the input. disabled.
        OP_AND                 = 0x84, //  x1 x2  out  Boolean and between each bit in the inputs. disabled.
        OP_OR                  = 0x85, //  x1 x2  out  Boolean or between each bit in the inputs. disabled.
        OP_XOR                 = 0x86, //  x1 x2  out  Boolean exclusive or between each bit in the inputs. disabled.


        // Reserved
        OP_RESERVED            = 0x50, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_VER                 = 0x62, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_VERIF               = 0x65, //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
        OP_VERNOTIF            = 0x66, //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
        OP_RESERVED1           = 0x89, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_RESERVED2           = 0x8a, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_NOP1                = 0xb0, // The word is ignored. Does not mark transaction as invalid.
        //OP_NOP2              = 0xb1, // Changed to OP_CHECKLOCKTIMEVERIFY
        //OP_NOP3              = 0xb2, // Changed to OP_CHECKSEQUENCEVERIFY
        OP_NOP4                = 0xb3, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP5                = 0xb4, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP6                = 0xb5, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP7                = 0xb6, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP8                = 0xb7, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP9                = 0xb8, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP10               = 0xb9, // The word is ignored. Does not mark transaction as invalid.

        OP_CHECKDATASIG        = 0xba,
        OP_CHECKDATASIGVERIFY  = 0xbb
    };

    class ScriptInterpreter
    {
    public:

        ScriptInterpreter()
        {
            mValid         = true;
            mVerified      = true;
            mStandard      = true;
            mTransaction   = NULL;
            mInputOffset   = 0;
            mInputSequence = 0xffffffff;
            mOutputAmount  = 0;
        }
        ~ScriptInterpreter() { clear(); }

        static void initializeStatic();

        void initialize(Transaction *pTransaction, unsigned int pOffset, uint32_t pSequence,
          int64_t pOutputAmount)
        {
            mTransaction = pTransaction;
            mInputOffset = pOffset;
            mInputSequence = pSequence;
            mOutputAmount = pOutputAmount;
        }

        // Process script
        bool process(NextCash::Buffer &pScript, int32_t pBlockVersion, Forks &pForks,
          unsigned int pBlockHeight);

        // No issues processing script
        bool isValid() { return mValid; }

        // Script verifies and signatures were all correct
        bool isVerified()
        {
            if(!mVerified)
                return false;

            if(mIfStack.size() > 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Not all if statements ended : %d", mIfStack.size());
                return false;
            }

            // Valid if top stack item is not zero
            if(mStack.size() > 0)
            {
                if(bufferIsZero(top()))
                    return false; // Top stack item is zero
                else
                    return true; // Top stack item is not zero
            }
            else
                return false; // Empty stack
        }

        bool stackIsClean()
        {
            if(!mVerified)
                return false;

            return mStack.size() == 1;
        }

        bool isStandard() { return mStandard; }

        void clear()
        {
            mValid         = true;
            mVerified      = true;
            mStandard      = true;
            mTransaction   = NULL;
            mInputOffset   = 0;
            mInputSequence = 0xffffffff;
            mOutputAmount  = 0;
            mHash.clear();

            std::list<NextCash::Buffer *>::iterator iter;
            for(iter = mStack.begin(); iter != mStack.end(); ++iter)
                delete *iter;
            mStack.clear();

            for(iter = mAltStack.begin(); iter != mAltStack.end(); ++iter)
                delete *iter;
            mAltStack.clear();

            mIfStack.clear();
            mAltIfStack.clear();
        }

        // For debugging
        void printStack(const char *pText);
        void printFailure(const char *pScriptName, NextCash::Buffer &pScript);

        enum ScriptType
        {
            NON_STANDARD, // Non standard script type
            INVALID, // Not a valid script
            P2PKH, // Pay to Public Key Hash
            /* Output Script : OP_DUP, OP_HASH160, <Hash160(PublicKey)>, OP_EQUALVERIFY, OP_CHECKSIG
             * Input Script  : <Signature> <PublicKey>
             *
             * Input script must provide a signature of the transaction corresponding to the public key.
             *   Then provide the public key with the hash specified in the output script.
             */
            P2PK, // Pay to Public Key
            /* Output Script : <PublicKey> OP_CHECKSIG
             * Input Script  : <Signature>
             *
             * Input script must provide a signature of the transaction corresponding with the public key in the output script.
             * This was deemed less secure than P2PKH since it provides the public key while the P2PKH does not.
             */
            P2SH, // Pay to Script Hash
            /* Output Script : OP_HASH160, <Hash160(RedeemScript)> OP_EQUAL
             * Input Script  : <RedeemScript>
             *
             * Input script must provide the redeem script with the hash specified in the output script.
             */
            MULTI_SIG, // Pay to MultiSignature Script
            /* Output Script : <RequiredSignatureCount> <PublicKey_1> <PublicKey_2> <PublicKey_X> <PublicKey_N> <PublicKeyCount> OP_CHECKMULTISIG
             * Input Script  : OP_0 <Signature_1> <Signature_2> <Signature_X> <Signature_N>
             *
             * Input script must provide RequiredSignatureCount signatures corresponding to and in the order of the public keys.
             * The maximum number of public keys is 16 since currently only "small integers" are allowed to specify count.
             */

            NULL_DATA  // Unspendable (Data Carrier)
            /* Output Script : OP_RETURN (Only data pushes)
             * Input Script  : Output is unspendable
             *
             * Output is unspendable and only data pushes
             */
        };

        static bool bufferIsZero(NextCash::Buffer *pBuffer);

        static bool isPushOnly(NextCash::Buffer &pScript);
        static bool isOPReturn(NextCash::Buffer &pScript)
        {
            return pScript.length() && *pScript.begin() == OP_RETURN;
        }
        static ScriptType parseOutputScript(NextCash::Buffer &pScript, NextCash::HashList &pHashes);
        static bool readDataPush(NextCash::Buffer &pScript, NextCash::Buffer &pData);

        static bool isSmallInteger(uint8_t pOpCode);
        static unsigned int smallIntegerValue(uint8_t pOpCode);
        static bool writeSmallInteger(unsigned int pValue, NextCash::Buffer &pScript);

        static void writeArithmeticInteger(NextCash::Buffer &pScript, int64_t pValue);
        static bool readArithmeticInteger(NextCash::Buffer &pScript, int64_t &pValue);

        static void removeCodeSeparators(NextCash::Buffer &pInputScript, NextCash::Buffer &pOutputScript);

        static NextCash::String coinBaseText(NextCash::Buffer &pScript,
          unsigned int pBlockVersion);
        static NextCash::String scriptText(NextCash::Buffer &pScript, const Forks &pForks,
          unsigned int pBlockHeight);
        static void printScript(NextCash::Buffer &pScript, const Forks &pForks,
          unsigned int pBlockHeight, NextCash::Log::Level pLevel = NextCash::Log::DEBUG);

        // Write to a script to push the following size of data to the stack
        static void writePushDataSize(unsigned int pSize, NextCash::OutputStream *pOutput);
        static bool pullData(uint8_t pOpCode, NextCash::Buffer &pScript, NextCash::Buffer &pData);

        static bool checkSignature(Transaction &pTransaction, unsigned int pInputOffset,
          int64_t pOutputAmount, const uint8_t *pPublicKeyData, unsigned int pPublicKeyDataSize,
          const uint8_t *pSignatureData, unsigned int pSignatureDataSize, bool pStrictSignatures,
          NextCash::Buffer &pCurrentOutputScript, unsigned int pSignatureStartOffset,
          const Forks &pForks, unsigned int pBlockHeight);

        static bool writeP2PKHOutputScript(NextCash::Buffer &pOutputScript,
          const NextCash::Hash &pPubKeyHash);

        static bool test();

        // For testing
        NextCash::Buffer *testElement(int pOffsetFromTop)
        {
            if(pOffsetFromTop < 0 || (unsigned int)pOffsetFromTop > mStack.size())
                return NULL;

            std::list<NextCash::Buffer *>::iterator result = mStack.end();

            for(int i=0;i<=(int)pOffsetFromTop;++i)
                --result;

            return *result;
        }

    private:

        // Returns the size of data pushed by the specified op code and script.
        // Returns 0xffffffff when op code is not a data push code, it is invalid, or if length is
        //   longer than script.
        // If pSkipData is true, then the "pushed data" will be skipped in the script.
        static unsigned int pullDataSize(uint8_t pOpCode, NextCash::Buffer &pScript,
          bool pSkipData = true);

        bool mValid;
        bool mVerified;
        bool mStandard;
        NextCash::Hash mHash;
        Transaction *mTransaction;
        unsigned int mInputOffset;
        uint32_t mInputSequence;
        int64_t mOutputAmount;

        std::list<NextCash::Buffer *> mStack, mAltStack;
        std::list<bool> mIfStack, mAltIfStack;

        bool ifStackTrue()
        {
            if(mIfStack.size() == 0)
                return true;

            for(std::list<bool>::iterator i = mIfStack.begin(); i != mIfStack.end(); ++i)
                if(!(*i))
                    return false;

            return true;
        }

        bool checkStackSize(unsigned int pMinimum) { return mStack.size() >= pMinimum; }
        bool checkAltStackSize(unsigned int pMinimum) { return mAltStack.size() >= pMinimum; }

        unsigned int popInteger()
        {
            NextCash::Buffer *buffer = top();
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
        NextCash::Buffer *push()
        {
            mStack.push_back(new NextCash::Buffer());
            mStack.back()->setInputEndian(NextCash::Endian::LITTLE); // Needed for arithmetic op codes to work
            return mStack.back();
        }
        void push(NextCash::Buffer *pValue) { mStack.push_back(pValue); }
        void pop(bool pDelete = true) { if(pDelete) delete mStack.back(); mStack.pop_back(); }
        NextCash::Buffer *top() { return mStack.back(); }
        bool stackIsEmpty() { return mStack.size() == 0; }

        // Alt Stack manipulation
        NextCash::Buffer *pushAlt()
        {
            mAltStack.push_back(new NextCash::Buffer());
            mAltStack.back()->setInputEndian(NextCash::Endian::LITTLE); // Needed for arithmetic op codes to work
            return mAltStack.back();
        }
        void pushAlt(NextCash::Buffer *pValue) { mAltStack.push_back(pValue); }
        void popAlt(bool pDelete = true) { if(pDelete) delete mAltStack.back(); mAltStack.pop_back(); }
        NextCash::Buffer *topAlt() { return mAltStack.back(); }
        bool stackAltIsEmpty() { return mAltStack.size() == 0; }

        static bool arithmeticRead(NextCash::Buffer *pBuffer, int64_t &pValue);
        static void arithmeticWrite(NextCash::Buffer *pBuffer, int64_t pValue);

        NextCash::stream_size mSigStartOffset;
        NextCash::Buffer *mScript;
        int32_t mBlockVersion;
        Forks *mForks;
        unsigned int mBlockHeight;

        static const char *sOpCodeNames[256];

        // Member function pointer array for op codes.
        static bool (ScriptInterpreter::*sExecuteOpCode[256])(uint8_t pOpCode);

        // Op Code functions
        bool opCodePushFalse(uint8_t pOpCode);
        bool opCodeSingleBytePush(uint8_t pOpCode);
        bool opCodePushData(uint8_t pOpCode);
        bool opCodePushNumber(uint8_t pOpCode);

        bool opCodeIf(uint8_t pOpCode);
        bool opCodeNotIf(uint8_t pOpCode);
        bool opCodeElse(uint8_t pOpCode);
        bool opCodeEndIf(uint8_t pOpCode);

        bool opCodeVerify(uint8_t pOpCode);
        bool opCodeReturn(uint8_t pOpCode);

        bool opCodeEqual(uint8_t pOpCode);

        bool opCodeHash(uint8_t pOpCode);

        bool opCodeSeparator(uint8_t pOpCode);

        bool opCodeCheckSig(uint8_t pOpCode);
        bool opCodeCheckMultiSig(uint8_t pOpCode);
        bool opCodeCheckDataSig(uint8_t pOpCode);

        bool opCodeCheckLockTimeVerify(uint8_t pOpCode);
        bool opCodeCheckSequenceVerify(uint8_t pOpCode);

        bool opCodeAdd1(uint8_t pOpCode);
        bool opCodeSubtract1(uint8_t pOpCode);
        bool opCodeNegate(uint8_t pOpCode);
        bool opCodeAbs(uint8_t pOpCode);
        bool opCodeNot(uint8_t pOpCode);
        bool opCodeZeroNotEqual(uint8_t pOpCode);
        bool opCodeAdd(uint8_t pOpCode);
        bool opCodeSubtract(uint8_t pOpCode);
        bool opCodeMultiply(uint8_t pOpCode);
        bool opCodeDivide(uint8_t pOpCode);
        bool opCodeMod(uint8_t pOpCode);

        bool opCodeLeftShift(uint8_t pOpCode);
        bool opCodeRightShift(uint8_t pOpCode);
        bool opCodeBoolAnd(uint8_t pOpCode);
        bool opCodeBoolOr(uint8_t pOpCode);

        bool opCodeNumEqual(uint8_t pOpCode);
        bool opCodeNumNotEqual(uint8_t pOpCode);
        bool opCodeLessThan(uint8_t pOpCode);
        bool opCodeGreaterThan(uint8_t pOpCode);
        bool opCodeLessThanOrEqual(uint8_t pOpCode);
        bool opCodeGreaterThanOrEqual(uint8_t pOpCode);
        bool opCodeMin(uint8_t pOpCode);
        bool opCodeMax(uint8_t pOpCode);
        bool opCodeWithin(uint8_t pOpCode);

        bool opCodeToAltStack(uint8_t pOpCode);
        bool opCodeFromAltStack(uint8_t pOpCode);
        bool opCodeDup(uint8_t pOpCode);
        bool opCodeIfDup(uint8_t pOpCode);
        bool opCodeDepth(uint8_t pOpCode);
        bool opCodeDrop(uint8_t pOpCode);
        bool opCodeNip(uint8_t pOpCode);
        bool opCodeOver(uint8_t pOpCode);
        bool opCodePick(uint8_t pOpCode);
        bool opCodeRoll(uint8_t pOpCode);
        bool opCodeRotate(uint8_t pOpCode);
        bool opCodeSwap(uint8_t pOpCode);
        bool opCodeTuck(uint8_t pOpCode);
        bool opCodeDrop2(uint8_t pOpCode);
        bool opCodeDup2(uint8_t pOpCode);
        bool opCodeDup3(uint8_t pOpCode);
        bool opCodeOver2(uint8_t pOpCode);
        bool opCodeRotate2(uint8_t pOpCode);
        bool opCodeSwap2(uint8_t pOpCode);

        bool opCodeConcat(uint8_t pOpCode);
        bool opCodeSplit(uint8_t pOpCode);
        bool opCodeNum2Bin(uint8_t pOpCode);
        bool opCodeBin2Num(uint8_t pOpCode);
        bool opCodeSize(uint8_t pOpCode);
        bool opCodeInvert(uint8_t pOpCode);

        bool opCodeAnd(uint8_t pOpCode);
        bool opCodeOr(uint8_t pOpCode);
        bool opCodeXor(uint8_t pOpCode);

        bool opCodeDisabled(uint8_t pOpCode);
        bool opCodeReserved(uint8_t pOpCode);
        bool opCodeNoOp(uint8_t pOpCode);
        bool opCodeUndefined(uint8_t pOpCode);
    };
}

#endif
