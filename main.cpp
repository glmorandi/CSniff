// Dear ImGui: standalone example application for GLFW + OpenGL 3, using
// programmable pipeline (GLFW is a cross-platform general purpose library for
// handling windows, inputs, OpenGL/Vulkan/Metal graphics context creation,
// etc.)

// Learn about Dear ImGui:
// - FAQ                  https://dearimgui.com/faq
// - Getting Started      https://dearimgui.com/getting-started
// - Documentation        https://dearimgui.com/docs (same as your local docs/
// folder).
// - Introduction, links and more at the top of imgui.cpp

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <stdio.h>
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif
#include "sniff.h"
#include <GLFW/glfw3.h> // Will drag system OpenGL headers
#include <utility>
#include <vector>
#include <fstream>

static PacketSniffer sniffer;
static std::vector<std::pair<int, unsigned char *>> capturedPackets;
static std::pair<int, unsigned char *> selected;

static void glfw_error_callback(int error, const char *description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

void drawMain()
{
    if (ImGui::BeginTabItem("Main"))
    {
        ImGui::Spacing();
        if (ImGui::Button("Begin capture"))
        {
            sniffer.startCapture(capturedPackets);
        }
        ImGui::SameLine();
        if (ImGui::Button("Stop capture"))
        {
            sniffer.stopCapture();
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear captured packets"))
        {
            // Since captured packets contain pointers to unsigned char arrays,
            // we delete[] each array to free the dynamically allocated memory
            for (auto packet : capturedPackets)
            {
                delete[] packet.second;
            }
            capturedPackets.clear();
        }
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Text("Writes the data of ALL captured packets to the file");
        static std::string filename(256, '\0');

        ImGui::InputText("Filename", &filename[0], filename.size());
        if (ImGui::Button("Write to file"))
        {
            std::ofstream file(filename);
            if (file.is_open())
            {
                for (auto p : capturedPackets)
                {
                    file << sniffer.printData(p);
                }
                file.close();
            }
            else
            {
                std::cerr << "Unable to open file" << std::endl;
            }
        }

        ImGui::Spacing();
        long packetQuantity = capturedPackets.size();
        ImGui::Text("Captured Packets: %ld", packetQuantity);

        ImGui::EndTabItem();
    }
}

void drawUpperPane()
{
    ImGui::BeginChild("upper pane",
                      ImVec2(ImGui::GetWindowWidth() - 15,
                             ImGui::GetWindowHeight() / 2),
                      ImGuiWindowFlags_NoScrollbar |
                          ImGuiWindowFlags_NoScrollWithMouse);
    if (ImGui::BeginTable("tab1", 4,
                          ImGuiTableFlags_BordersOuter |
                              ImGuiTableFlags_BordersV |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_SizingStretchSame))
    {
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Destination");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableSetupColumn("Size");
        ImGui::TableHeadersRow();

        for (long unsigned int i = 0; i < capturedPackets.size(); i++)
        {
            const auto &data = capturedPackets[i];

            struct ethhdr *eth =
                reinterpret_cast<struct ethhdr *>(data.second);

            char source[64];
            char dest[64];
            char proto[16];
            char size[64];
            snprintf(source, sizeof(source), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                     eth->h_source[0], eth->h_source[1], eth->h_source[2],
                     eth->h_source[3], eth->h_source[4], eth->h_source[5]);
            snprintf(dest, sizeof(dest), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                     eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                     eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
            snprintf(proto, sizeof(proto), "%u",
                     static_cast<unsigned short>(eth->h_proto));
            snprintf(size, sizeof(size), "%d", (data.first));
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(source, selected == capturedPackets[i],
                                  ImGuiSelectableFlags_AllowDoubleClick |
                                      ImGuiSelectableFlags_SpanAllColumns))
                selected = capturedPackets[i];
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(dest, selected == capturedPackets[i],
                                  ImGuiSelectableFlags_AllowDoubleClick |
                                      ImGuiSelectableFlags_SpanAllColumns))
                selected = capturedPackets[i];
            ImGui::TableSetColumnIndex(2);
            if (ImGui::Selectable(proto, selected == capturedPackets[i],
                                  ImGuiSelectableFlags_AllowDoubleClick |
                                      ImGuiSelectableFlags_SpanAllColumns))
                selected = capturedPackets[i];
            ImGui::TableSetColumnIndex(3);
            if (ImGui::Selectable(size, selected == capturedPackets[i],
                                  ImGuiSelectableFlags_AllowDoubleClick |
                                      ImGuiSelectableFlags_SpanAllColumns))
                selected = capturedPackets[i];
            ImGui::TableNextRow();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

void drawLowerPane()
{
    ImGui::BeginChild("bottom pane",
                      ImVec2(ImGui::GetWindowWidth() - 15,
                             ImGui::GetWindowHeight() / 2),
                      ImGuiChildFlags_Border);
    if (ImGui::TreeNode("Ethernet Header"))
    {
        if (selected.first)
        {
            struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(selected.second);
            ImGui::Text("Destination Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                        eth->h_source[0], eth->h_source[1], eth->h_source[2],
                        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
            ImGui::Text("Source Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
            ImGui::Text("Protocol: %u",
                        static_cast<unsigned short>(eth->h_proto));
        }
        else
            ImGui::Text("No packet selected");
        ImGui::TreePop();
    }
    if (ImGui::TreeNode("IP Header"))
    {
        if (selected.first)
        {
            struct iphdr *iph =
                (struct iphdr *)(selected.second +
                                 sizeof(struct ethhdr));
            struct sockaddr_in source, dest;
            source.sin_addr.s_addr = iph->saddr;
            dest.sin_addr.s_addr = iph->daddr;
            ImGui::Text("IP Version: %d", iph->version);
            ImGui::Text("IP Header Length: %d bytes\n",
                        ((unsigned int)(iph->ihl)) * 4);
            ImGui::Text("Type Of Service: %d\n", (unsigned int)iph->tos);
            ImGui::Text("IP Total Length: %d  bytes (Size of Packet)\n",
                        ntohs(iph->tot_len));
            ImGui::Text("Identification: %d\n", ntohs(iph->id));
            ImGui::Text("TTL: %d\n", (unsigned int)iph->ttl);
            ImGui::Text("Protocol: %d\n", (unsigned int)iph->protocol);
            ImGui::Text("Checksum: %d\n", ntohs(iph->check));
            ImGui::Text("Source IP: %s\n", inet_ntoa(source.sin_addr));
            ImGui::Text("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
        }
        else
            ImGui::Text("No packet selected");
        ImGui::TreePop();
    }
    ImGui::EndChild();
}

void drawCapturedPackets()
{
    if (ImGui::BeginTabItem("Capture Packets"))
    {
        ImGui::Spacing();
        drawUpperPane();
        drawLowerPane();
        ImGui::EndTabItem();
    }
}

void drawAbout()
{
    if (ImGui::BeginTabItem("About"))
    {
        ImGui::Spacing();
        ImGui::TextWrapped("This program serves as a packet sniffer designed to capture network packets traversing a network interface.\nIt provides a user interface to display information about each captured packet, including data extracted from both the Ethernet header and the IP header.\nThe packet sniffer operates by listening for packets on the network interface using raw sockets.");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Text("github.com/glmorandi");
        ImGui::Text("Developed using ImGUI and C++");

        ImGui::EndTabItem();
    }
}

// Main code
int main(int, char **)
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

        // Decide GL+GLSL versions
#if defined(IMGUI_IMPL_OPENGL_ES2)
    // GL ES 2.0 + GLSL 100
    const char *glsl_version = "#version 100";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(__APPLE__)
    // GL 3.2 + GLSL 150
    const char *glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);           // Required on Mac
#else
    // GL 3.0 + GLSL 130
    const char *glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    // glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+
    // only glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE); // 3.0+ only
#endif

    // Create window with graphics context
    GLFWwindow *window = glfwCreateWindow(1280, 720, "Sniffer", nullptr, nullptr);
    if (window == nullptr)
        return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |=
        ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
    io.ConfigFlags |=
        ImGuiConfigFlags_NavEnableGamepad; // Enable Gamepad Controls

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    // ImGui::StyleColorsLight();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
#ifdef __EMSCRIPTEN__
    ImGui_ImplGlfw_InstallEmscriptenCanvasResizeCallback("#canvas");
#endif
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Load Fonts
    // - If no fonts are loaded, dear imgui will use the default font. You can
    // also load multiple fonts and use ImGui::PushFont()/PopFont() to select
    // them.
    // - AddFontFromFileTTF() will return the ImFont* so you can store it if you
    // need to select the font among multiple.
    // - If the file cannot be loaded, the function will return a nullptr. Please
    // handle those errors in your application (e.g. use an assertion, or display
    // an error and quit).
    // - The fonts will be rasterized at a given size (w/ oversampling) and stored
    // into a texture when calling ImFontAtlas::Build()/GetTexDataAsXXXX(), which
    // ImGui_ImplXXXX_NewFrame below will call.
    // - Use '#define IMGUI_ENABLE_FREETYPE' in your imconfig file to use Freetype
    // for higher quality font rendering.
    // - Read 'docs/FONTS.md' for more instructions and details.
    // - Remember that in C/C++ if you want to include a backslash \ in a string
    // literal you need to write a double backslash \\ !
    // - Our Emscripten build process allows embedding fonts to be accessible at
    // runtime from the "fonts/" folder. See Makefile.emscripten for details.
    // io.Fonts->AddFontDefault();
    // io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\segoeui.ttf", 18.0f);
    // io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
    // io.Fonts->AddFontFromFileTTF("../../misc/fonts/Roboto-Medium.ttf", 16.0f);
    // io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
    io.Fonts->AddFontFromFileTTF(
        "/usr/share/fonts/opentype/fira/FiraMono-Regular.otf", 18.0f);
    io.IniFilename = NULL;
    // ImFont* font =
    // io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\ArialUni.ttf", 18.0f,
    // nullptr, io.Fonts->GetGlyphRangesJapanese()); IM_ASSERT(font != nullptr);

    // Main loop
#ifdef __EMSCRIPTEN__
    // For an Emscripten build we are disabling file-system access, so let's not
    // attempt to do a fopen() of the imgui.ini file. You may manually call
    // LoadIniSettingsFromMemory() to load settings from your own storage.
    io.IniFilename = nullptr;
    EMSCRIPTEN_MAINLOOP_BEGIN
#else
    while (!glfwWindowShouldClose(window))
#endif
    {
        // Poll and handle events (inputs, window resize, etc.)
        // You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to
        // tell if dear imgui wants to use your inputs.
        // - When io.WantCaptureMouse is true, do not dispatch mouse input data to
        // your main application, or clear/overwrite your copy of the mouse data.
        // - When io.WantCaptureKeyboard is true, do not dispatch keyboard input
        // data to your main application, or clear/overwrite your copy of the
        // keyboard data. Generally you may always pass all inputs to dear imgui,
        // and hide them from your application based on those two flags.
        glfwPollEvents();

        // Start the Dear ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // 2. Show a simple window that we create ourselves. We use a Begin/End pair
        // to create a named window.
        {
            ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
            ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

            ImGui::Begin("Packet Sniffer", NULL,
                         ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoDecoration |
                             ImGuiWindowFlags_NoSavedSettings);

            if (ImGui::BeginTabBar("Main"))
            {
                drawMain();
                drawCapturedPackets();
                drawAbout();
                if(ImGui::BeginTabItem("Style")){
                    ImGui::ShowStyleEditor();
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::End();
        }
        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        // glClearColor(clear_color.x * clear_color.w, clear_color.y *
        // clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }
#ifdef __EMSCRIPTEN__
    EMSCRIPTEN_MAINLOOP_END;
#endif

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
