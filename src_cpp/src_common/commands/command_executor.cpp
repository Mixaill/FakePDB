#include "commands/command_executor.h"

namespace FakePDB{
    void CommandExecutor::AddCommand(std::shared_ptr<CommandInterface> i)  {
        _commands.push_back(i);
    }

    int CommandExecutor::Run(int argc, char **argv)  {
        if (argc < 2) {
            Usage();
            return 0;
        }

        std::string command_name = argv[1];
        for (auto& command : _commands) {
            //check name
            if (command->GetCommandName() != command_name) {
                continue;
            }

            //check arg count
            if (argc-2 < command->GetArgsMin() || argc-2 > command->GetArgsMax()) {
                std::cerr << "Invalid number of arguments" << std::endl;
                for (auto& usage : command->GetCommandUsage()) {
                    std::cout << "Usage      : " << command->GetCommandName() << " " << usage << std::endl;
                }
            }

            //run
            return command->Run(argc, argv);
        }

        std::cerr << "Command not found" << std::endl;
        Usage();
        return 1;
    }

    void CommandExecutor::Usage(){
        std::cout << "Available commands" << std::endl << std::endl;

        for (auto& command : _commands) {
            std::cout << "Name       : " << command->GetCommandName() << std::endl;
            std::cout << "Description: " << command->GetCommandDescription() << std::endl;
            for (auto& usage : command->GetCommandUsage()) {
                std::cout << "Usage      : " << command->GetCommandName() << " " << usage << std::endl;
            }

            std::cout << std::endl;
        }
    }

}
