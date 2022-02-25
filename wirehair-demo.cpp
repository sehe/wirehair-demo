#undef NDEBUG
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <thread>
using namespace std::chrono_literals;
using std::this_thread::sleep_for;

#include <boost/asio.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <wirehair/wirehair.h>

namespace asio = boost::asio;
namespace fs   = std::filesystem;
using asio::ip::udp;

static constexpr int      PACKET_SIZE  = 1400;
static constexpr uint16_t DEFAULT_PORT = 9797;

namespace /*protocol*/ {
#pragma pack(push, 1)
    struct file_info {
        boost::endian::big_uint32_t    magic;
        boost::endian::big_uint64_t    file_length;
        boost::uuids::uuid             xfer_id;
        std::array<char, PATH_MAX + 1> name;

        enum : unsigned {
            MAGIC     = 0xDEFACED,
            HEADERLEN = sizeof(magic) + sizeof(file_length) + sizeof(xfer_id),
        };
    };
    static_assert(std::is_trivial_v<file_info>);
    static_assert(sizeof(file_info) + 8 <= 0xFFFF); // must fit udp

    struct packet_info {
        boost::endian::big_uint32_t      magic, block_length, id;
        boost::uuids::uuid               xfer_id;
        std::array<uint8_t, PACKET_SIZE> block;
        enum : unsigned {
            MAGIC     = static_cast<unsigned>(~0xDEFACED),
            HEADERLEN = sizeof(magic) + sizeof(block_length) + sizeof(id) + sizeof(xfer_id)
        };
    };
    static_assert(std::is_trivial_v<packet_info>);
    static_assert(sizeof(packet_info) + 8 <= 0xFFFF); // must fit udp
#pragma pack(pop)

    // Rule Of Zero, please:
    struct WHFree {
        void operator()(WirehairCodec c) const { wirehair_free(c); }
    };

    using CodecPtr = std::unique_ptr<WirehairCodec_t, WHFree>;
} // namespace

struct UDPclient {
    UDPclient(asio::any_io_executor ex, uint16_t port = DEFAULT_PORT)
        : socket_(ex, udp::v4())
        , port_(port)
    {
        socket_.bind({{}, port_});
    }

    bool run()
    {
        file_info fi{}; // value-initializes all members

        udp::endpoint sender;
        if (std::size_t n =
                socket_.receive_from(asio::buffer(&fi, sizeof(fi)), sender);
            n > file_info::HEADERLEN && fi.magic == file_info::MAGIC) //
        {
            // don't assume name will be zero terminated
            std::string_view name(fi.name.data(),
                                  strnlen(fi.name.data(), fi.name.max_size()));

            std::cout << "Receiving " << fi.xfer_id << " length "
                      << fi.file_length << " name " << std::quoted(name)
                      << " from " << sender << std::endl;
            decoder_.reset(
                wirehair_decoder_create(nullptr, fi.file_length, PACKET_SIZE));

            if (!decoder_) {
                throw std::runtime_error("wirehair_decoder_create");
            }

            packet_info packet{};

            for (bool data_complete = false; !data_complete;) {
                if (auto len = socket_.receive_from(
                        asio::buffer(&packet, sizeof(packet)), sender);
                    n >= packet_info::HEADERLEN &&
                    packet.magic == packet_info::MAGIC &&
                    len == packet_info::HEADERLEN + packet.block_length) //
                {
                    if (fi.xfer_id != packet.xfer_id)
                        continue; // TODO concurrent receives

                    std::cout << "(Incoming " << packet.block_length << " for "
                              << fi.xfer_id << " from " << sender << ")"
                              << std::endl;
                    // Attempt decode
                    switch (wirehair_decode(decoder_.get(), packet.id,
                                            packet.block.data(),
                                            packet.block_length)) //
                    {
                        case Wirehair_NeedMore: continue; break;
                        case Wirehair_Success: data_complete = true; break;
                        default: throw std::runtime_error("wirehair_decode");
                    }
                    std::cout << "(data complete? " << std::boolalpha
                              << data_complete << ")" << std::endl;
                }
            }
            std::cout << "Receive completed for " << fi.xfer_id << std::endl;

            // try to be safe about interpreting the output name
            auto spec = fs::relative(
                weakly_canonical(
                    relative_path /
                    fs::path(name).lexically_normal().relative_path()),
                relative_path);

            if (spec.empty())
                throw std::runtime_error("invalid file specification " + spec.native());

            auto target = relative_path / spec;
            fs::create_directories(target.parent_path());

            std::cout << "Decoding to " << target << " for " << fi.xfer_id
                      << std::endl;
            std::vector<uint8_t> decoded(fi.file_length);

            // Recover original data on decoder side
            auto r = wirehair_recover(decoder_.get(), decoded.data(),
                    decoded.size());

            if (r != Wirehair_Success)
                throw std::runtime_error("wirehair_recover");

            std::ofstream(target, std::ios::binary)
                .write(reinterpret_cast<char const*>(decoded.data()),
                       decoded.size());
        }
        return true;
    }

  private:
    udp::socket socket_;
    uint16_t    port_;
    CodecPtr    decoder_{};
    fs::path    relative_path = "assets/";
};

struct Sender {
    Sender(asio::any_io_executor ex, uint16_t port = DEFAULT_PORT)
        : socket_(ex, udp::v4())
        , port_(port)
    {
    }

    bool send(fs::path filespec)
    {
        std::ifstream ifs(filespec, std::ios::binary);
        std::vector<uint8_t> const contents(std::istreambuf_iterator<char>(ifs),
                                            {});
        ifs.close();
        assert(contents.size() == fs::file_size(filespec));

        file_info fi{}; // value-initializes all members
        fi.magic       = file_info::MAGIC;
        fi.xfer_id     = boost::uuids::random_generator{}();
        fi.file_length = contents.size();
        strncpy(fi.name.data(), filespec.c_str(), fi.name.size() - 1);

        socket_.send_to(asio::buffer(&fi, sizeof(fi)), {{}, port_});

        // Create encoder
        encoder_.reset(wirehair_encoder_create(nullptr, contents.data(),
                                               contents.size(), PACKET_SIZE));
        if (!encoder_) {
            throw std::runtime_error("wirehair_encoder_create");
        }

        auto N = contents.size() / PACKET_SIZE + 1;
        N      = (N * 10) / 9; // ~10% redundancy

        std::cout << "Sending " << filespec << " of " << contents.size()
                  << " bytes in " << N << " packets of " << PACKET_SIZE
                  << std::endl;

        for (unsigned block_id = 1; block_id <= N; ++block_id) {
            sleep_for(10ms);
            packet_info packet{};
            packet.magic   = packet_info::MAGIC;
            packet.xfer_id = fi.xfer_id;

            // Encode a packet
            uint32_t writeLen = 0;
            if (auto r = wirehair_encode(encoder_.get(), block_id,
                                         packet.block.data(),
                                         packet.block.size(), &writeLen);
                r == Wirehair_Success) //
            {
                packet.id           = block_id;
                packet.block_length = writeLen;
                socket_.send_to(
                    asio::buffer(&packet, packet_info::HEADERLEN + writeLen),
                    {{}, port_});
                std::cout << "(Packet " << packet.block_length << " bytes)"
                          << std::endl;
            } else {
                throw std::runtime_error("wirehair_encode");
            }
        }

        std::cout << "Send " << filespec << " complete (xfer_id:" << fi.xfer_id
                  << ")" << std::endl;
        return true;
    }

  private:
    udp::socket socket_;
    uint16_t    port_;
    CodecPtr    encoder_{};
    fs::path    relative_path = "assets/";
};

int main(int argc, char** argv) {
    if (auto r = wirehair_init(); r != Wirehair_Success) {
        std::cout << "Wirehair initialization failed: " << r << std::endl;
        return 1;
    }

    asio::thread_pool io(1); 
    auto ex = io.get_executor();

    post(io, [ex] {
        UDPclient client{ex};
        while (true)
        try { client.run(); }
        catch (std::exception const& e) { std::cout << "Exception: " << e.what() << "\n"; }
    });

    Sender sender{ex};
    for (auto spec : std::vector(argv + 1, argv + argc)) {
        try {
            sender.send(spec);
        } catch (std::exception const& e) {
            std::cout << "Exception: " << e.what() << "\n";
        }
    }

    io.join();
}
