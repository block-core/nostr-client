using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Nostr.Client.Requests;
using Xunit;

public class NostrFilterTests 
{
    [Fact]
    public void SubjectFilter_SerializesCorrectly()
    {
        var filter = new NostrFilter
        {
            Subject = new[] { "test subject", "another subject" }
        };

        var json = JsonConvert.SerializeObject(filter);
        
        Assert.Contains("\"#subject\":[\"test subject\",\"another subject\"]", json);
    }

    [Fact]
    public void SubjectFilter_DeserializesCorrectly()
    {
        var json = "{\"#subject\":[\"test subject\",\"another subject\"]}";
        
        var filter = JsonConvert.DeserializeObject<NostrFilter>(json);
        
        Assert.NotNull(filter.Subject);
        Assert.Equal(2, filter.Subject.Length);
        Assert.Equal("test subject", filter.Subject[0]);
        Assert.Equal("another subject", filter.Subject[1]);
    }

    [Fact]
    public void DynamicTags_SerializeCorrectly()
    {
        var filter = new NostrFilter();
        filter.AddTag("custom", "value1", "value2");
        filter.AddTag("other", "test");

        var json = JsonConvert.SerializeObject(filter);
        var parsed = JObject.Parse(json);
        
        Assert.Equal(new[] { "value1", "value2" }, parsed["#custom"].Select(x => x.ToString()));
        Assert.Equal(new[] { "test" }, parsed["#other"].Select(x => x.ToString()));
    }

    [Fact]
    public void DynamicTags_DeserializeCorrectly()
    {
        var json = "{\"#custom\":[\"value1\",\"value2\"],\"#other\":[\"test\"]}";
        var filter = JsonConvert.DeserializeObject<NostrFilter>(json);
        
        Assert.Equal(2, filter.Tags.Count);
        Assert.True(filter.Tags.ContainsKey("#custom"));
        Assert.True(filter.Tags.ContainsKey("#other"));
        
        var customValues = filter.Tags["#custom"].ToObject<string[]>();
        Assert.Equal(new[] { "value1", "value2" }, customValues);
        
        var otherValues = filter.Tags["#other"].ToObject<string[]>();
        Assert.Equal(new[] { "test" }, otherValues);
    }

    [Fact]
    public void RemoveTag_RemovesTagFromFilter()
    {
        var filter = new NostrFilter();
        filter.AddTag("custom", "value1");
        
        var removed = filter.RemoveTag("custom");
        
        Assert.True(removed);
        Assert.Empty(filter.Tags);
    }

    [Fact]
    public void RemoveTag_WithNonExistentTag_ReturnsFalse()
    {
        var filter = new NostrFilter();
        
        var removed = filter.RemoveTag("nonexistent");
        
        Assert.False(removed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void AddTag_WithInvalidTagName_ThrowsArgumentNullException(string tagName)
    {
        var filter = new NostrFilter();
        
        Assert.Throws<ArgumentNullException>(() => filter.AddTag(tagName, "value"));
    }

    [Fact]
    public void AddTag_WithEmptyValues_CreatesEmptyArray()
    {
        var filter = new NostrFilter();
        filter.AddTag("custom");

        var json = JsonConvert.SerializeObject(filter);
        var parsed = JObject.Parse(json);
        
        Assert.Empty(parsed["#custom"]);
    }
}