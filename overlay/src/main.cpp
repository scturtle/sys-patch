#include "minIni/minIni.h"
#include <string_view>
#define STBTT_STATIC
#define TESLA_INIT_IMPL
#include "tesla.hpp"

namespace {

constexpr auto CONFIG_PATH = "/config/sys-patch/config.ini";
constexpr auto LOG_PATH = "/config/sys-patch/log.ini";

auto does_file_exist(const char *path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    FsFile file{};
    char path_buf[FS_MAX_PATH]{};
    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }
    strcpy(path_buf, path);
    rc = fsFsOpenFile(&fs, path_buf, FsOpenMode_Read, &file);
    fsFileClose(&file);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

// creates a directory, non-recursive!
auto create_dir(const char *path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    char path_buf[FS_MAX_PATH]{};
    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }
    strcpy(path_buf, path);
    rc = fsFsCreateDirectory(&fs, path_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

struct ConfigEntry {
    ConfigEntry(const char *_section, const char *_key, bool default_value)
        : section{_section}, key{_key} {
        this->value = ini_getbool(this->section, this->key, default_value, CONFIG_PATH);
    }

    auto create_list_item(const char *text) {
        auto item = new tsl::elm::ToggleListItem(text, value);
        item->setStateChangedListener([this](bool new_value) {
            this->value = new_value;
            ini_putl(this->section, this->key, this->value, CONFIG_PATH);
        });
        return item;
    }

    const char *const section;
    const char *const key;
    bool value;
};

class GuiOptions final : public tsl::Gui {
  public:
    tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        list->addItem(new tsl::elm::CategoryHeader("Options"));
        list->addItem(config_patch_emummc.create_list_item("Patch emuMMC"));

        frame->setContent(list);
        return frame;
    }

    ConfigEntry config_patch_emummc{"options", "patch_emummc", true};
};

class GuiToggle final : public tsl::Gui {
  public:
    tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        list->addItem(new tsl::elm::CategoryHeader("FS - 0100000000000000"));
        list->addItem(config_noncasigchk.create_list_item("noncasigchk"));

        list->addItem(new tsl::elm::CategoryHeader("LDR - 0100000000000001"));
        list->addItem(config_noacidsigchk.create_list_item("noacidsigchk"));

        list->addItem(new tsl::elm::CategoryHeader("ES - 0100000000000033"));
        list->addItem(config_es.create_list_item("es"));

        list->addItem(new tsl::elm::CategoryHeader("NIFM - 010000000000000F"));
        list->addItem(config_ctest.create_list_item("ctest"));

        frame->setContent(list);
        return frame;
    }

    ConfigEntry config_noncasigchk{"fs", "noncasigchk", true};
    ConfigEntry config_noacidsigchk{"ldr", "noacidsigchk", true};
    ConfigEntry config_es{"es", "es", true};
    ConfigEntry config_ctest{"nifm", "ctest", false};
};

class GuiLog final : public tsl::Gui {
  public:
    tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        if (does_file_exist(LOG_PATH)) {
            struct CallbackUser {
                tsl::elm::List *list;
                std::string last_section;
            } callback_userdata{list};

            ini_browse([](const mTCHAR *Section, const mTCHAR *Key, const mTCHAR *Value, void *UserData) {
                auto user = (CallbackUser *)UserData;
                std::string_view value{Value};

                if (value == "Skipped") {
                    return 1;
                }

                if (user->last_section != Section) {
                    user->last_section = Section;
                    user->list->addItem(new tsl::elm::CategoryHeader("Log: " + user->last_section));
                }

                if (value.starts_with("Patched")) {
                    if (value.ends_with("(sys-patch)")) {
                        user->list->addItem(new tsl::elm::ListItem(Key, "Patched"));
                    } else {
                        user->list->addItem(new tsl::elm::ListItem(Key, "Patched"));
                    }
                } else if (value.starts_with("Unpatched") || value.starts_with("Disabled")) {
                    user->list->addItem(new tsl::elm::ListItem(Key, Value));
                } else if (user->last_section == "stats") {
                    user->list->addItem(new tsl::elm::ListItem(Key, Value));
                } else {
                    user->list->addItem(new tsl::elm::ListItem(Key, Value));
                }

                return 1;
            },
                       &callback_userdata, LOG_PATH);
        } else {
            list->addItem(new tsl::elm::ListItem("No log found!"));
        }

        frame->setContent(list);
        return frame;
    }
};

class GuiMain final : public tsl::Gui {
  public:
    tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        auto options = new tsl::elm::ListItem("Options");
        auto toggle = new tsl::elm::ListItem("Toggle patches");
        auto log = new tsl::elm::ListItem("Log");

        options->setClickListener([](u64 keys) -> bool {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<GuiOptions>();
                return true;
            }
            return false;
        });

        toggle->setClickListener([](u64 keys) -> bool {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<GuiToggle>();
                return true;
            }
            return false;
        });

        log->setClickListener([](u64 keys) -> bool {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<GuiLog>();
                return true;
            }
            return false;
        });

        list->addItem(new tsl::elm::CategoryHeader("Menu"));
        list->addItem(options);
        list->addItem(toggle);
        list->addItem(log);

        frame->setContent(list);
        return frame;
    }
};

// libtesla already initialized fs, hid, pl, pmdmnt, hid:sys and set:sys
class SysPatchOverlay final : public tsl::Overlay {
  public:
    std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<GuiMain>();
    }
};

} // namespace

int main(int argc, char **argv) {
    create_dir("/config/");
    create_dir("/config/sys-patch/");
    return tsl::loop<SysPatchOverlay>(argc, argv);
}
