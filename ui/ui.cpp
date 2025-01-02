#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/screen/string.hpp>

#include <iostream>
#include <sys/ioctl.h>

#include "ui.hpp"


screen screen_size;

screen get_terminal_size() {
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &screen_size);
}

int main() {
  
  /*
  using namespace ftxui;

  Element document = 
    hbox({
      text("left")   | border,
      text("middle") | border | flex,
      text("right")  | border,
    });      

  auto screen = Screen::Create(
    Dimension::Full(),       // Width
    Dimension::Fit(document) // Height
  );
  Render(screen, document);
  screen.Print();

  return EXIT_SUCCESS;

  const std::string string = "Hello World! This is an example of the FTXUI libary!";

  ftxui::Element doc = ftxui::hbox(
    ftxui::text(string) | ftxui::border | ftxui::flex,
    ftxui::text("This should flex to fill the space") | ftxui::border | ftxui::flex,
    ftxui::text("This is a Test -- should be at the right side!") | ftxui::border | ftxui::flex
  );

  ftxui::Screen screen = ftxui::Screen::Create(
    ftxui::Dimension::Full(), //Fixed(string.length() + 2),
    ftxui::Dimension::Fit(doc) //Fixed(3)
  );

  ftxui::Render(screen, doc);
  screen.Print();
  std::cout << "\n";
  
  auto window = ftxui::window(
    ftxui::text(" Test Window ") | ftxui::center | ftxui::bold,
    ftxui::vbox({
      ftxui::separator(),
      ftxui::text("This is the content of the window.") | ftxui::center | ftxui::color(ftxui::Color::Blue),
      ftxui::text("You can add more elements here.") | ftxui::center | ftxui::color(ftxui::Color::Green)
    })
  );

  auto screen = ftxui::Screen::Create(ftxui::Dimension::Full(), ftxui::Dimension::Full());

  while (true) {
    auto [cols, rows] = GetTerminalSize();

    if (screen->Size().x != cols || screen->Size().y != rows) {
      screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(cols), ftxui::Dimension::Fixed(rows));
    
      ftxui::Render(screen, window);
      screen.Print();  // Print the rendered screen
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  std::cout << std::endl;

  return EXIT_SUCCESS;
  */

  //screen

  /*
  auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(32), ftxui::Dimension::Fixed(10));
 
  auto& pixel = screen.PixelAt(9,9);
  pixel.character = U'A';
  pixel.bold = true;
  pixel.foreground_color = ftxui::Color::Blue;
  */

  ftxui::Element doc = ftxui::hbox(
    //ftxui::text(string) | ftxui::border | ftxui::flex,
    ftxui::text("This should flex to fill the space") | ftxui::border | ftxui::flex,
    ftxui::text("This is a Test -- should be at the right side!") | ftxui::border | ftxui::flex,
    ftxui::border(ftxui::gauge(0.5))
  );

  //doc = ftxui::border{doc};
  //doc = doc | ftxui::border.
  //doc |= ftxui::border;

  ftxui::Screen screen_ = ftxui::Screen::Create(
    ftxui::Dimension::Fixed(screen_size.x), //Fixed(string.length() + 2),
    ftxui::Dimension::Fixed(screen_size.y) //Fixed(3)
  );

  ftxui::Render(screen_, doc);
  screen.Print();
  std::cout << "\n";

  //std::cout << screen.ToString();
  return EXIT_SUCCESS;
}
