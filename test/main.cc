#include "test.h"
#include "rsa-test.h"

INITIALIZE_EASYLOGGINGPP

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
    el::Loggers::addFlag(el::LoggingFlag::ImmediateFlush);

    return ::testing::UnitTest::GetInstance()->Run();
}
