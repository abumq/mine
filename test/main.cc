#include "test.h"
#include "zlib-test.h"
#include "aes-test.h"
#include "base64-test.h"
#include "base16-test.h"
#include "big-integer-test.h"
#include "rsa-test.h"

INITIALIZE_EASYLOGGINGPP

void disableLogs() {
    el::Loggers::reconfigureAllLoggers(el::Level::Global, el::ConfigurationType::Enabled, "false");
}

int main(int argc, char** argv) {

    ::testing::InitGoogleTest(&argc, argv);
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
    el::Loggers::addFlag(el::LoggingFlag::ImmediateFlush);
    //disableLogs();

    return ::testing::UnitTest::GetInstance()->Run();
}
