#include "smokeBomb.h"

using namespace llvm;

namespace {
struct smokeBombPass : public FunctionPass {
	public:
    static char ID;
    smokeBombPass() : FunctionPass(ID) {}

	bool doInitialization(Module &M) override;
	bool runOnFunction(Function &F) override;

	private:
	// Helper functions
	bool iterateOnFunction(Function &F);
	bool isAnnotatedWithSmokeBomb(Module *M, GlobalVariable *GV);
	void setSmokeBombFunc(Module *M);
	bool insertCallInstBeforeInsn(Module *M, Instruction *StartInsn, Instruction *EndInsn, Function *F, Value *GV, unsigned long Size);
	bool insertCallInstAfterInsn(Module *M, Instruction *StartInsn, Instruction *EndInsn, Function *F, Value *GV, unsigned long Size);
	bool insertDummyCallInstBeforeInsn(Instruction *I, Instruction **Start);
	bool insertDummyCallInstAfterInsn(Instruction *I);

	// init/exit function
	Function *SmokeBombInitFunc;
	Function *SmokeBombExitFunc;
	Function *SmokeBombDummyInitFunc;
	Function *SmokeBombDummyExitFunc;
  };
}

char smokeBombPass::ID = 0;

bool smokeBombPass::insertDummyCallInstBeforeInsn(Instruction *I, Instruction **Start) {
	CallInst *CI = NULL;
	CI = CallInst::Create(SmokeBombDummyInitFunc, "", I);
	CI->setTailCall(false);

/*
	if (I == *Start) {
		// setup start again
		*Start = (Instruction *)CI;
	}*/
	return true;
}

bool smokeBombPass::insertDummyCallInstAfterInsn(Instruction *I) {
/*
	Instruction *NextI = NULL;
	CallInst *CI = NULL;
	BasicBlock *BB = I->getParent();

	for (BasicBlock::iterator BI = BB->begin(), BE = BB->end(); BI != BE;) {
		NextI = &*BI++;
		if (NextI == I && (&*BI) != BE) {
			NextI = &*BI;
			break;
		}
	}
	if (NextI) {
		CI = CallInst::Create(SmokeBombDummyExitFunc, "", NextI);
		CI->setTailCall(false);
	}*/
	return true;
}

bool smokeBombPass::insertCallInstBeforeInsn(Module *M, Instruction *StartInsn, Instruction *EndInsn, Function *F, Value *GV, unsigned long Size) {
	LLVMContext &C = M->getContext();
	//Value *V = StartInsn->getOperand(0);
	Value *V = GV;
	Constant *size = Constant::getIntegerValue(IntegerType::getInt64Ty(C), APInt(64, Size));
	Value *params[] = {
		V,
		size,
	};
	BasicBlock *StartBB = StartInsn->getParent();
	BasicBlock *EndBB = EndInsn->getParent();
	CallInst *CI = NULL;

	if (false /*StartBB == EndBB*/) {
		CI = CallInst::Create(SmokeBombInitFunc, params, "", StartInsn);
		CI->setTailCall(false);
	}
	else {
		/* Insert at the front of Function for safety */
		Instruction &I = (F->front()).front();
		CI = CallInst::Create(SmokeBombInitFunc, params, "", &I);
		CI->setTailCall(false);
	}
	return true;
}

bool smokeBombPass::insertCallInstAfterInsn(Module *M, Instruction *StartInsn, Instruction *EndInsn, Function *F, Value *GV, unsigned long Size) {
	LLVMContext &C = M->getContext();
	//Value *V = EndInsn->getOperand(0);
	Value *V = GV;
	Constant *size = Constant::getIntegerValue(IntegerType::getInt64Ty(C), APInt(64, Size));
	Value *params[] = {
		V,
		size,
	};
	BasicBlock *StartBB = StartInsn->getParent();
	BasicBlock *EndBB = EndInsn->getParent();
	CallInst *CI = NULL;

	if (false /*StartBB == EndBB*/) {
		Instruction *NextI = NULL;
		for (BasicBlock::iterator BI = StartBB->begin(), BE = StartBB->end(); BI != BE;) {
			NextI = &*BI++;
			if (NextI == EndInsn && (&*BI) != BE) {
				NextI = &*BI;
				break;
			}
		}
		CI = CallInst::Create(SmokeBombExitFunc, params, "", NextI);
		CI->setTailCall(false);
	}
	else {
		/* Insert at the end of Function for safety */
		Instruction &I = (F->back()).back();
		CI = CallInst::Create(SmokeBombExitFunc, params, "", &I);
		CI->setTailCall(false);
	}
	
	return true;
}

void smokeBombPass::setSmokeBombFunc(Module *M) {
	LLVMContext &Context = M->getContext();
	Constant *C = M->getOrInsertFunction("smoke_bomb_init", Type::getVoidTy(Context), PointerType::getUnqual(Type::getInt32Ty(Context)), Type::getInt64Ty(Context), nullptr);
	SmokeBombInitFunc = dyn_cast<Function>(C);
	
	C = M->getOrInsertFunction("smoke_bomb_exit", Type::getVoidTy(Context), PointerType::getUnqual(Type::getInt32Ty(Context)), Type::getInt64Ty(Context), nullptr);
	SmokeBombExitFunc = dyn_cast<Function>(C);

	C = M->getOrInsertFunction("smoke_bomb_dummy_init", Type::getVoidTy(Context), Type::getVoidTy(Context), nullptr);
	SmokeBombDummyInitFunc = dyn_cast<Function>(C);

	C = M->getOrInsertFunction("smoke_bomb_dummy_exit", Type::getVoidTy(Context), Type::getVoidTy(Context), nullptr);
	SmokeBombDummyExitFunc = dyn_cast<Function>(C);

	errs() << SmokeBombInitFunc->getName() << "," << SmokeBombExitFunc->getName() << "," << SmokeBombDummyInitFunc->getName() << "," << SmokeBombDummyExitFunc->getName() << "\n";
}

bool smokeBombPass::doInitialization(Module &M) {
	setSmokeBombFunc(&M);
	return false;
}

bool smokeBombPass::isAnnotatedWithSmokeBomb(Module *M, GlobalVariable *GV) {
	for (Module::global_iterator I = M->global_begin(), E = M->global_end(); I != E; ++I) {
		if (I->getName() == "llvm.global.annotations") {
			ConstantArray *CA = dyn_cast<ConstantArray>(I->getOperand(0));
			for(auto OI = CA->op_begin(); OI != CA->op_end(); ++OI){
				ConstantStruct *CS = dyn_cast<ConstantStruct>(OI->get());
				if (CS->getOperand(0)->getOperand(0)->getValueID() != Value::GlobalVariableVal)
					continue;

				GlobalVariable *AnnotationGL = dyn_cast<GlobalVariable>(CS->getOperand(1)->getOperand(0));
				GlobalVariable *AnnotationGV = dyn_cast<GlobalVariable>(CS->getOperand(0)->getOperand(0));
				StringRef annotation = dyn_cast<ConstantDataArray>(AnnotationGL->getInitializer())->getAsCString();
				if (GV == AnnotationGV && annotation.compare("smokeBomb") == 0) {
					errs() << AnnotationGV->getName() << " is annotated with " << annotation << "!!\n";
					return true;
				}
			}
		}
	}
	return false;
}

bool smokeBombPass::runOnFunction(Function &F) {
	errs() << "====== " << F.getName() << " =======\n";
	iterateOnFunction(F);
    return false;
}

/*
 * Find senstive area automatically
 *
 * Case-1) If start and end are in same basic block, ==> Insert init/exit before/after "Instruction"
 * Case-2) If start and end are not in same basic block, ==> Insert init/exit before/after "BasicBlock" (Not supported yet)
 */

bool smokeBombPass::iterateOnFunction(Function &F) {
	Instruction *StartInsn = NULL;
	Instruction *EndInsn = NULL;
	Value *SensitiveGV = NULL;
	unsigned long SensitiveSize = 0;
	Module *M = NULL;
	bool flag = false;

	// Walk all instruction in the function.
	for (Function::iterator BB = F.begin(), BBE = F.end(); BB != BBE; ++BB) {
		for (BasicBlock::iterator BI = BB->begin(), BE = BB->end(); BI != BE;) {
			// Avoid invalidating the iterator.
			Instruction *I = &*BI++;
			Value *V;
			GlobalVariable *GV;

			/* GetElementPtr first */
			if (GetElementPtrInst *PI = dyn_cast<GetElementPtrInst>(I)) {
				V = PI->getOperand(0);
				if (V->getValueID() == Value::GlobalVariableVal) {
					GV = dyn_cast<GlobalVariable>(V);
					M = GV->getParent();
					flag = isAnnotatedWithSmokeBomb(M, GV);
					if (flag == true) {
						DataLayout DL(M);
						EndInsn = I;
						if (StartInsn == NULL) {
							StartInsn = I;
							SensitiveGV = V;
							SensitiveSize = DL.getTypeSizeInBits(GV->getValueType()) / 8;
						}
						insertDummyCallInstBeforeInsn(I, &StartInsn);
						insertDummyCallInstAfterInsn(I);
						continue;
					}
				}
			}

			if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
				V = SI->getPointerOperand();
				errs() << F.getName() << " : " << "StoreInst! - " << V->getName() << "\n";
				if (V->getValueID() == Value::GlobalVariableVal) {
					GV = dyn_cast<GlobalVariable>(V);
					M = GV->getParent();
					flag = isAnnotatedWithSmokeBomb(M, GV);
					if (flag == true) {
						DataLayout DL(M);
						EndInsn = I;
						if (StartInsn == NULL) {
							StartInsn = I;
							SensitiveGV = V;
							SensitiveSize = DL.getTypeSizeInBits(GV->getValueType()) / 8;
						}
						insertDummyCallInstBeforeInsn(I, &StartInsn);
						insertDummyCallInstAfterInsn(I);
					}
				}
			}
			else if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
				V = LI->getPointerOperand();
				if (V->getValueID() == Value::GlobalVariableVal) {
					errs() << F.getName() << " : " << "LoadInst! - " << V->getName() << "\n";
					GV = dyn_cast<GlobalVariable>(V);
					M = GV->getParent();
					flag = isAnnotatedWithSmokeBomb(M, GV);
					if (flag == true) {
						DataLayout DL(M);
						EndInsn = I;
						if (StartInsn == NULL) {
							StartInsn = I;
							SensitiveGV = V;
							SensitiveSize = DL.getTypeSizeInBits(GV->getValueType()) / 8;
						}
						insertDummyCallInstBeforeInsn(I, &StartInsn);
						insertDummyCallInstAfterInsn(I);
					}
				}
				else if (V->getValueID() == Value::ConstantExprVal) {
					/* array case. int arr[N][N]; */
					ConstantExpr *CE = dyn_cast<ConstantExpr>(V);
					Value *CV = CE->getOperand(0);
					CV->dump();
					if (CV->getValueID() == Value::GlobalVariableVal) {
						errs() << F.getName() << " : " << "LoadInst! - " << CV->getName() << "\n";
						GV = dyn_cast<GlobalVariable>(CV);
						M = GV->getParent();
						
						flag = isAnnotatedWithSmokeBomb(M, GV);
						Type *T = GV->getValueType();
						if (flag == true && T->isArrayTy()) {
							DataLayout DL(M);
							/*
							Constant *C = GV->getInitializer();
							ConstantArray *arr;
							Constant *elem;
							Value *ElemV;

							arr = cast<ConstantArray>(C);
							elem = arr->getOperand(0);
							ElemV = cast<Value>(elem);
							num1 = cast<ArrayType>(T)->getNumElements();
							errs() << "getElementByteSize : " << DL.getTypeSizeInBits(T) / 8 << "\n";
							if (ElemV->getType()->isArrayTy()) {
								num2 = cast<ArrayType>(ElemV->getType())->getNumElements();
								errs() << "getElementByteSize : " << DL.getTypeSizeInBits(ElemV->getType()) / 8 << "\n";
							}*/
							
							BasicBlock *BBI = &*BB;
							IRBuilder<> Builder(BBI);
							LLVMContext &Context = M->getContext();
							Value *ArrV = Builder.CreateBitCast(GV, PointerType::getUnqual(Type::getInt32Ty(Context)));

							EndInsn = I;
							if (StartInsn == NULL) {
								StartInsn = I;
								SensitiveGV = (Value *)ArrV;
								SensitiveSize = DL.getTypeSizeInBits(T) / 8;
							}
							insertDummyCallInstBeforeInsn(I, &StartInsn);
							insertDummyCallInstAfterInsn(I);
						}
					}
				}
			}
		}
	}
	errs() << "BasicBlocks : " << F.size() << "\n";

	if (StartInsn && EndInsn && SensitiveGV) {
		/*
		errs() << "start : ";
		StartInsn->dump();
		errs() << "end : ";
		EndInsn->dump(); */

		insertCallInstBeforeInsn(M, StartInsn, EndInsn, &F, SensitiveGV, SensitiveSize);
		insertCallInstAfterInsn(M, StartInsn, EndInsn, &F, SensitiveGV, SensitiveSize);
	}

	return true;
}

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html

static void registersmokeBombPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new smokeBombPass());
}
static RegisterStandardPasses RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible, registersmokeBombPass);